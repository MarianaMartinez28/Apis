from flask import Flask, render_template, request, jsonify
import requests
from requests.auth import HTTPBasicAuth
import json

app = Flask(__name__)

# Configuración de conexión al router
ROUTER_IP = '192.168.56.105'
USERNAME = 'cisco'
PASSWORD = 'cisco123!'
BASE_URL = f'https://{ROUTER_IP}/restconf'

# Desactivar las advertencias de SSL (no recomendable para producción)
requests.packages.urllib3.disable_warnings()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/interfaces', methods=['GET'])
def get_interfaces_info():
    url = f'{BASE_URL}/data/ietf-interfaces:interfaces'
    response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD),
                            headers={'Accept': 'application/yang-data+json'}, verify=False)

    if response.status_code == 200:
        interfaces = format_interfaces_info(response.json())
        return jsonify({'interfaces': interfaces}), 200
    else:
        return jsonify({'error': f'Error al obtener la información de las interfaces: {response.status_code}'}), 500


@app.route('/hostname', methods=['POST'])
def set_hostname():
    data = request.get_json()
    hostname = data.get('hostname')
    url = f'{BASE_URL}/data/Cisco-IOS-XE-native:native/hostname'
    headers = {
        'Content-Type': 'application/yang-data+json',
        'Accept': 'application/yang-data+json'
    }
    payload = {
        "Cisco-IOS-XE-native:hostname": hostname
    }

    response = requests.put(url, auth=HTTPBasicAuth(USERNAME, PASSWORD), headers=headers, data=json.dumps(payload),
                            verify=False)

    if response.status_code in [200, 201, 204]:
        return jsonify({'message': f'Hostname actualizado a {hostname} correctamente.'}), 200
    else:
        return jsonify({'error': f'Error al actualizar el hostname: {response.status_code}'}), 500


def format_interfaces_info(info):
    formatted_info = []
    interfaces = info.get('ietf-interfaces:interfaces', {}).get('interface', [])
    for iface in interfaces:
        interface_info = {
            'name': iface.get('name'),
            'type': iface.get('type')
        }
        if 'ietf-ip:ipv4' in iface:
            for address in iface['ietf-ip:ipv4'].get('address', []):
                interface_info['ipv4_address'] = address.get('ip')
                interface_info['subnet_mask'] = address.get('netmask')
        formatted_info.append(interface_info)
    return formatted_info


if __name__ == '__main__':
    app.run(debug=True)
