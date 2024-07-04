import socket
import threading
import pickle
import select

urls = {}


PORT = 53
IP = '127.0.0.1'
MSG_SIZE = 512
HEADER_LENGTH = 12
POINTER_HEADER = 49152  # = 11000000 00000000
URL_POINTER = HEADER_LENGTH + POINTER_HEADER
TTL = b'\x00\x00\x00d'  # = 100 sec
A = b'\x00\x01'
AAAA = b'\x00\x1c'
PTR = b'\x00\x0c'
TYPES = {A: 'A', AAAA: 'AAAA', PTR: 'PTR'}

ADDRESS_TYPE = 'ADDRESS_TYPE'
IP_TYPE = 'IP_TYPE'
SET = 'SET'
REMOVE = 'REMOVE'
SHOW = 'SHOW'
SAVE = 'SAVE'
LOAD = 'LOAD'
EXIT = 'EXIT'
HELP = 'HELP'
FIND = 'FIND'
BLANK = tuple()
COMMANDS = {SET: (ADDRESS_TYPE, IP_TYPE), REMOVE: (ADDRESS_TYPE, ), SHOW: BLANK, SAVE: BLANK, LOAD: BLANK, EXIT: BLANK,
            HELP: BLANK, FIND: (IP_TYPE, )}
CONF_FILE = 'conf'
TOP_LEVEL_DOMAINS = ['com', 'co.il']


def get_flags(flags):
    bin_str = bin(int.from_bytes(flags, 'big')).replace('0b', '')
    bin_str = '0'*(16 - len(bin_str)) + bin_str
    qr = int(bin_str[0], 2)
    opcode = int(bin_str[1:5], 2)
    aa = int(bin_str[5], 2)
    tc = int(bin_str[6], 2)
    rd = int(bin_str[7], 2)
    ra = int(bin_str[8], 2)
    z = int(bin_str[9:12], 2)
    rcode = int(bin_str[12:16], 2)
    return qr, opcode, aa, tc, rd, ra, z, rcode


def get_header(data):
    index, flags, qd_c, an_c, ns_c, ar_c = data[:2], data[2:4], data[4:6], data[6:8], data[8:10], data[10:12]
    qr, opcode, aa, tc, rd, ra, z, rcode = get_flags(flags)
    return index, qr, opcode, aa, tc, rd, ra, z, rcode, qd_c, an_c, ns_c, ar_c


def get_url(body):
    length = body[0]
    i = 1
    url_parts = []
    current_part = []
    while length:
        current_part.append(body[i])
        length -= 1
        i += 1
        if length == 0:
            url_parts.append(''.join([chr(x) for x in current_part]))
            current_part = []
            length = body[i]
            i += 1
    return '.'.join(url_parts)


def get_body(body):
    url = get_url(body)
    index = len(url) + 2
    q_type = body[index: index+2]
    q_class = body[index+2: index+4]
    return url, q_type, q_class


def ip_bytes(ip):
    ip_b = b''
    for b in ip.split('.'):
        ip_b += int(b).to_bytes(1, 'big')
    return ip_b


def set_response(index, q_class, qd_c, q_type, opcode, body, url):
    bin_opcode = bin(opcode).strip('0b')
    bin_opcode = '0' * (4 - len(bin_opcode)) + bin_opcode
    if url in urls and q_type == A:
        header = index + int(f'1{bin_opcode}10000000000', 2).to_bytes(2, 'big') + qd_c + qd_c + b'\x00\x00\x00\x00'
        ip = b'\x00\x04' + ip_bytes(urls[url])
        answer = URL_POINTER.to_bytes(2, 'big') + q_type + q_class + TTL + ip
        return header + body + answer
    else:
        header = index + int(f'1{bin_opcode}10000000011', 2).to_bytes(2, 'big') + qd_c + b'\x00\x00\x00\x00\x00\x00'
        return header + body


def is_type(value, t):
    if not value:
        return False
    elif t in [str, int, float]:
        try:
            t(value)
        except ValueError:
            return False
    elif t == IP_TYPE:
        numbers = value.split('.')
        if len(numbers) != 4:
            return False
        try:
            for number in numbers:
                if not 0 <= int(number) < 255:
                    return False
        except ValueError:
            return False
    elif t == ADDRESS_TYPE:
        parts = value.split('.', 2)
        if len(parts) != 3:
            return False
        if parts[0] != 'www' and parts[2] not in TOP_LEVEL_DOMAINS:
            return False
    else:
        return False
    return True


def check_ui_input(ui_input):
    ui_input = ui_input.strip(' ')
    if not ui_input:
        return None, []
    command = ui_input.split(' ')[0]
    if command not in COMMANDS:
        return None, []
    n_of_v = len(ui_input.split(' ')) - 1
    if not n_of_v == len(COMMANDS[command]):
        return None, []
    values = ui_input.split(' ')[1:]
    for i, value in enumerate(values):
        if not is_type(value, COMMANDS[command][i]):
            return None, []
    return command, values


def show_help():
    strings = []
    for command, values in COMMANDS.items():
        values_string = ''
        for value in values:
            if value == ADDRESS_TYPE:
                values_string += '<url address> '
            elif value == IP_TYPE:
                values_string += '<ip> '
            else:
                values_string += f'<{value}>'
        strings.append(f'{command} {values_string}')
    return '\n'.join(strings)


def set_ui(settings):
    def has_change():
        return last_urls != urls

    def comm_set():
        u, ip = values
        urls[u] = ip

    def comm_remove():
        u, = values
        try:
            urls.pop(u)
        except KeyError:
            print('Error! url not found!')

    def comm_show():
        for u in urls:
            ip = urls[u]
            print(f'{u} -> {ip}')

    def comm_save():
        with open(CONF_FILE, 'wb') as conf:
            conf.write(pickle.dumps(urls))
        last_urls_keys = list(last_urls)
        for key in last_urls_keys:
            last_urls.pop(key)
        for item in urls:
            last_urls[item] = urls[item]

    def comm_load():
        try:
            with open(CONF_FILE, 'rb') as conf:
                items = pickle.loads(conf.read())
            keys = list(urls.keys())
            for item in keys:
                urls.pop(item)
            for item in items:
                urls[item] = items[item]
        except Exception as e:
            print(f'error! could not open file! {e}')

    def comm_exit():
        settings['running'] = False

    def comm_help():
        print(show_help())

    def comm_find():
        ip, = values
        for k, v in urls.items():
            if v == ip:
                print(f'{ip} found at {k}')
                return
        print(f'{ip} not found!')

    commands_func = {SET: comm_set, REMOVE: comm_remove, SHOW: comm_show, SAVE: comm_save, LOAD: comm_load,
                     EXIT: comm_exit, HELP: comm_help, FIND: comm_find}

    print('hello! enter commands here:')
    comm_load()
    last_urls = {}
    for url in urls:
        last_urls[url] = urls[url]
    while settings['running']:
        ui_input = input(f'command{"*" if has_change() else ""}: ')
        command, values = check_ui_input(ui_input)
        if not command:
            print('error!')
            continue
        commands_func[command]()


def main():
    settings = {'running': True}
    ui_thread = threading.Thread(target=set_ui, args=[settings])
    ui_thread.start()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((IP, PORT))
    while settings['running']:
        try:
            r, _, _ = select.select([server], [], [], 0)
            if r:
                data, addr = server.recvfrom(MSG_SIZE)
            else:
                continue
        except ConnectionResetError:
            continue
        body = data[HEADER_LENGTH:]
        index, qr, opcode, aa, tc, rd, ra, z, rcode, qd_c, an_c, ns_c, ar_c = get_header(data)
        url, q_type, q_class = get_body(body)
        server.sendto(set_response(index, q_class, qd_c, q_type, opcode, body, url), addr)


if __name__ == '__main__':
    main()
