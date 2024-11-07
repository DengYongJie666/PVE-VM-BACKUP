import requests
import json
import time
import urllib3
from threading import Semaphore


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_config(file_path):
    with open(file_path, 'r') as file:
        config = json.load(file)
    return config


def authenticate(base_url, username, password):
    auth_url = f"{base_url}/access/ticket"
    data = {
        "username": username,
        "password": password
    }
    # 发送身份验证请求
    response = requests.post(auth_url, data=data, verify=False)
    if response.status_code == 200:
        result = response.json()
        if 'data' in result and 'ticket' in result['data'] and 'CSRFPreventionToken' in result['data']:
            ticket = result['data']['ticket']
            csrf_prevention_token = result['data']['CSRFPreventionToken']
            sess.cookies.set('PVEAuthCookie', ticket)
            return csrf_prevention_token
        else:
            raise Exception(f"Unexpected response data: {json.dumps(result, indent=4)}")
    else:
        raise Exception(f"Authentication failed: {response.status_code} - {response.text}")


def start_backup(base_url, backup_node, backup_id, csrf_prevention_token):
    url = f"{base_url}/nodes/{backup_node}/vzdump"
    headers = {
        "CSRFPreventionToken": csrf_prevention_token
    }
    backup_data = {
        "vmid": backup_id,
        "node": backup_node,
        "compress": "zstd"
    }
    response = sess.post(url, data=backup_data, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to start backup: {response.status_code} - {response.text}")


def get_task_status(base_url, backup_node, task_id, csrf_prevention_token):
    url = f"{base_url}/nodes/{backup_node}/tasks/{task_id}/status"
    headers = {
        "CSRFPreventionToken": csrf_prevention_token
    }
    response = sess.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to get task status: {response.status_code} - {response.text}")


def get_task_log(base_url, backup_node, task_id, csrf_prevention_token):
    url = f"{base_url}/nodes/{backup_node}/tasks/{task_id}/log"
    headers = {
        "CSRFPreventionToken": csrf_prevention_token
    }
    response = sess.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"get task log: {response.status_code} - {response.text}")


def print_task_info(base_url, backup_node, task_id, csrf_prevention_token):
    last_log_length = 0

    while True:
        task_status = get_task_status(base_url, backup_node, task_id, csrf_prevention_token)

        if task_status['data']['status'] == 'running':
            task_log = get_task_log(base_url, backup_node, task_id, csrf_prevention_token)
            new_log = task_log['data'][last_log_length:]
            if new_log:
                print("New Task Log Entries:")
                print(json.dumps(new_log, indent=4))

            last_log_length = len(task_log['data'])
        elif task_status['data']['status'] == 'failed':
            print(f"Backup task failed: {task_status['data']['status']}")
            break
        else:
            print(f"Backup task completed: {task_status['data']['status']}")
            break
        time.sleep(1)
    print("Final Task Status:", json.dumps(task_status, indent=4))


def check_backup_status(base_url, backup_node, backup_id, csrf_prevention_token):
    url = f"{base_url}/cluster/tasks/"
    headers = {
        "CSRFPreventionToken": csrf_prevention_token
    }
    response = sess.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        tasks = response.json().get('data', [])
        matching_tasks = []
        for task in tasks:
            upid = task.get('upid')

            if upid and upid.startswith(f"UPID:{backup_node}:") and f"vzdump:{backup_id}" in upid:
                if task.get('type') == 'vzdump' and task.get('saved') == '0':
                    matching_tasks.append(task)
        if matching_tasks:
            print(f"Found {len(matching_tasks)} matching backup tasks for VM {backup_id}:")
            for task in matching_tasks:
                print(json.dumps(task, indent=4))
            return True
    else:
        raise Exception(f"Failed to check backup status: {response.status_code} - {response.text}")


def retry_on_timeout(func, *args, max_retries=3, delay=2):
    for attempt in range(max_retries + 1):
        try:
            return func(*args)
        except Exception as e:
            if attempt < max_retries:
                print(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print(f"Attempt {attempt + 1} failed: {e}. No more retries.")
                raise

if __name__ == "__main__":
    try:
        config = read_config('config.json')
        base_url = config['pve_url']
        username = config['username']
        password = config['password']
        backups = config['backups']

        sess = requests.session()

        csrf_prevention_token = authenticate(base_url, username, password)

        semaphore = Semaphore(3)

        with open('unexecuted_backups_vm.txt', 'w') as unexecuted_file:
            for backup in backups:
                backup_node = backup['node']
                backup_ids = backup['ids']

                for backup_id in backup_ids:
                    print(backup_node)
                    print(backup_id)

                    if check_backup_status(base_url, backup_node, backup_id, csrf_prevention_token):
                        print(f"Another backup task is already running for VM {backup_id} on node {backup_node}. Skipping.")
                        # 记录未执行的备份任务
                        unexecuted_file.write(f"VM ID: {backup_id}, Node: {backup_node}\n")
                        continue

                    semaphore.acquire()

                    try:

                        backup_info = retry_on_timeout(start_backup, base_url, backup_node, backup_id, csrf_prevention_token)
                        print(f"Backup Task Started for VM {backup_id} on node {backup_node}:")
                        print(json.dumps(backup_info, indent=4))

                        task_id = backup_info['data']
                        print_task_info(base_url, backup_node, task_id, csrf_prevention_token)
                    finally:
                        semaphore.release()

    except Exception as e:
        print(f"Error: {e}")
