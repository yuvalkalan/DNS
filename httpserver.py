import socket


def is_func(item):
    return item.count('?') < 0


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 80))
    server.listen()
    while True:
        try:
            client, addr = server.accept()
            data = client.recv(1024).decode('utf-8')
            to_get = data.split()[1]
        except IndexError:
            continue
        print(data, f'to get: {to_get}', sep='\n')
        if is_func(to_get):
            func, value = to_get[1:].split('?')
            if func == 'calculate-next':
                client.send(f'{int(value)+1}'.encode())
        else:
            if to_get == '/':
                file = r'root.html'
            else:
                file = to_get[1:]
            try:
                with open(file, 'rb') as my_file:
                    client.send(my_file.read())
            except OSError:
                pass
        client.close()


if __name__ == '__main__':
    main()