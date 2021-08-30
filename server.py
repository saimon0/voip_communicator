import pyaudio
import socket
import threading
import database
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime, timedelta

db = database.Database()

chunk = 1024
pa = pyaudio.PyAudio()
pa.get_default_input_device_info()

stream = pa.open(format=pyaudio.paInt16,
                 channels=1,
                 rate=10240,
                 output=True,
                 input=True,
                 )

# Socket Initialization
host = '192.168.1.64'
port = 12345
size = 1024
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host, port))


DISCONNECT = '!DISCONNECT'
LOGIN = '!LOGIN'
LOGGED_IN = '!LOGGED_IN'
ALREADY_LOGGED = '!ALREADY_LOGGED'
NON_EXISTS = '!NON_EXISTS'
REGISTER = '!REGISTER'
CALL_REQUEST = '!CALL_REQUEST'
CALL_REQUEST_ACC = '!CALL_REQUEST_ACC'
CALL_REQUEST_DCC = '!CALL_REQUEST_DCC'
CALL_END = '!CALL_END'
WRONG_PASS = '!WRONG_PASS'
USER_EXISTS = '!USER_EXISTS'
REGISTERED = '!REGISTERED'
LOGOUT = '!LOGOUT'
MAKE_CALL = '!MAKE_CALL'
GET_FRIENDS = '!GET_FRIENDS'
GET_HISTORY = '!GET_HISTORY'
REFRESH_HISTORY = '!REFRESH_HISTORY'

connected_users = {}
active_calls = []
clients_keys = {}

client_connected = '!CLIENT_CONNECTED$$$ACK'
client_connected_bytes = client_connected.encode()
call_is_alive = False


def encrypt_message(conn, data):
    client_key = clients_keys.get(conn)
    pub_key = RSA.importKey(client_key)
    encryptor = PKCS1_OAEP.new(pub_key)
    encoded_data = data.encode()
    return encryptor.encrypt(encoded_data)


def handle_client_requests(conn, addr):
    global connected_users, clients_keys, call_is_alive
    print(f"[NEW CLIENT] {addr} connected\n\n")
    connected = True
    while connected:
        is_audio_message = False
        raw_msg = conn.recv(size)
        if conn in clients_keys.keys():
            try:
                decryptor = PKCS1_OAEP.new(key)
                decryptor.decrypt(raw_msg)
            except ValueError:
                is_audio_message = True
            if is_audio_message is True:
                send_speak_msg_to_proper_receiver(conn, raw_msg)
                conn.send(raw_msg)
            else:
                decryptor = PKCS1_OAEP.new(key)
                raw_msg = decryptor.decrypt(raw_msg)
                raw_msg.decode()
                if True:
                    msg = raw_msg.decode()
                    msg_arr = msg.split('$$$')
                    msg_code = msg.split("$$$")[0]
                    msg_content = msg
                    if msg_code == DISCONNECT:
                        connected = False
                    elif msg_code == LOGIN:
                        method_result = handle_login_request(msg_content, conn)
                        if method_result == NON_EXISTS:
                            d = encrypt_message(conn, NON_EXISTS)
                            conn.send(d)
                        elif method_result == LOGGED_IN:
                            resp = LOGGED_IN + '$$$' + msg_content.split('$$$')[1] + '$$$' + str(key)
                            resp = encrypt_message(conn, resp)
                            conn.send(resp)
                        elif method_result == ALREADY_LOGGED:
                            resp = ALREADY_LOGGED
                            conn.send(encrypt_message(conn, resp))
                        else:
                            conn.send(encrypt_message(conn, WRONG_PASS))
                    elif msg_code == REGISTER:
                        if handle_register_request(msg_content) == USER_EXISTS:
                            conn.send(encrypt_message(conn, USER_EXISTS))
                        else:
                            conn.send(encrypt_message(conn, REGISTERED))
                    elif msg_code == GET_FRIENDS:
                        user_friends = get_user_friends()
                        msg = GET_FRIENDS + '@'
                        for a in user_friends:
                            if len(str(a[0])) > 0:
                                msg = msg + str(a[0]) + '@'
                        conn.send(encrypt_message(conn, msg))
                    elif msg_code == MAKE_CALL:
                        msg_content = msg_content.split('@')
                        request_author = msg_content[1]
                        request_receiver = msg_content[2]
                        handle_call_request(request_author, request_receiver)
                    elif msg_code == LOGOUT:
                        handle_logout_request(conn, msg_content)
                    elif msg_code == CALL_REQUEST:
                        handle_call_request_response(msg_arr)
                    elif msg_code == CALL_END:
                        handle_call_finish(msg_arr)
                    elif msg_code == GET_HISTORY or msg_code == REFRESH_HISTORY:
                        handle_history_calls(conn, msg_arr[1])
        else:
            clients_keys[conn] = raw_msg
            conn.send(public)
    conn.close()


def handle_history_calls(conn, msg_arr):
    user = msg_arr
    db.cursor.execute('SELECT * FROM conversations WHERE author = ? OR receiver = ?', (user, user))
    results = db.cursor.fetchall()
    if len(results) == 0:
        msg = '!GET_HISTORY$$$NO_HISTORY'
        conn.send(encrypt_message(conn, msg))
    else:
        msg = '!GET_HISTORY$$$'
        for a in results:
            row = str(a)
            msg += row + '$$$'
        conn.send(encrypt_message(conn, msg))


def send_speak_msg_to_proper_receiver(conn, speak_msg):
    user_sender = list(connected_users.keys())[list(connected_users.values()).index(conn)]
    receiver = ''

    for call in active_calls:
        if call["author"] == user_sender:
            receiver = connected_users.get(call['receiver'])
        elif call['receiver'] == user_sender:
            receiver = connected_users.get(call['author'])

    receiver.send(speak_msg)


def handle_call_finish(msg_arr):
    global active_calls, call_is_alive
    call_is_alive = False
    call_instance = ''
    conversation_author = ''
    conversation_receiver = ''
    second_user_to_inform = ''

    if len(msg_arr) == 2:
        request_end_call_user = msg_arr[1]
        conversation_author = ''
        conversation_receiver = ''
        msg = ''

        for call in active_calls:
            if call["author"] == request_end_call_user:
                call_instance = call
                conversation_author = call['author']
                conversation_receiver = call['receiver']
                second_user_to_inform = call['receiver']
                msg = '!CALL_END$$$' + conversation_author

                break
            elif call['receiver'] == request_end_call_user:
                call_instance = call
                conversation_author = call['author']
                conversation_receiver = call['receiver']
                second_user_to_inform = call['author']
                msg = '!CALL_END$$$' + conversation_author
                break

        second_user_conn = connected_users.get(second_user_to_inform)
        second_user_conn.send(encrypt_message(second_user_conn, msg))

    elif msg_arr[0] == CALL_END and msg_arr[2] == 'CONVERSATION_SAVE':
        call_start_time = msg_arr[3]
        splitted_start_datetime = call_start_time.split(' ')
        start_hour = splitted_start_datetime[1]

        call_end_time = msg_arr[4]
        splitted_end_datetime = call_end_time.split(' ')
        end_hour = splitted_end_datetime[1]
        hour_start = datetime.strptime(start_hour.split('.')[0], '%H:%M:%S')
        hour_end = datetime.strptime(end_hour.split('.')[0], '%H:%M:%S')
        call_duration = hour_end - hour_start
        call_duration_seconds = call_duration.total_seconds()
        author = msg_arr[1]
        receiver = ''

        for call in active_calls:
            if author == call['author']:
                receiver = call['receiver']
                call_instance = call
            else:
                receiver = call['author']
                author = call['receiver']
                call_instance = call

        call_duration_seconds_formatted = str(timedelta(seconds=call_duration_seconds))

        start_hour = str(hour_start).split(' ')[1]

        row = (None, author, receiver, splitted_start_datetime[0], start_hour, call_duration_seconds_formatted)

        db.cursor.execute('INSERT INTO conversations VALUES (?, ?, ?, ?, ?, ?)', row)
        db.conn.commit()

        author_conn = connected_users.get(author)
        receiver_conn = connected_users.get(receiver)

        handle_history_calls(author_conn, author)
        handle_history_calls(receiver_conn, receiver)

        if len(active_calls) > 0:
            active_calls.remove(call_instance)


def create_call_instance(request_author, request_receiver):
    global active_calls
    active_call = {'author': request_author, 'receiver': request_receiver}
    active_calls.append(active_call)


def handle_call_request_response(msg_arr):
    global call_is_alive
    request_author = msg_arr[1]
    request_call_decision = msg_arr[2]
    decision = msg_arr[2]
    request_receiver = msg_arr[3]
    if decision == 'ACCEPT':
        create_call_instance(request_author, request_receiver)
        author_conn = connected_users.get(request_author)
        msg = '!CALL_REQUEST_ACC$$$ACCEPTANCE$$$' + str(request_receiver)
        call_is_alive = True
        author_conn.send(encrypt_message(author_conn, msg))
    elif decision == 'DECLINE':
        author_conn = connected_users.get(request_author)
        msg = '!CALL_REQUEST_DCC$$$DECLINE$$$' + str(request_author)
        encoded_msg = bytes(msg, 'utf-8')
        author_conn.send(encrypt_message(author_conn, msg))


def handle_login_request(msg, conn):
    login_data = msg.split('$$$')
    login = login_data[1]
    password = login_data[2]
    user_data = db.cursor.execute('SELECT username, password FROM users WHERE username = ?', (login,)).fetchone()
    if user_data == None:
        return NON_EXISTS
    else:
        if login in connected_users:
            return ALREADY_LOGGED
        if user_data[0] == login and user_data[1] == password:
            connected_users[login] = conn
            return LOGGED_IN


def handle_logout_request(conn, msg):
    global connected_users
    copy = connected_users
    login = msg.split("$$$")[1]
    del copy[login]
    connected_users = copy
    msg = '!LOGOUT'
    conn.send(encrypt_message(conn, msg))


def handle_register_request(msg):
    register_data = msg.split('$$$')
    login = register_data[1]
    password = register_data[2]
    row = (None, login, password)
    val = db.cursor.execute('SELECT username FROM users WHERE username = ?', (login,)).fetchone()
    if val == None:
        db.cursor.execute('INSERT INTO users VALUES (?, ?, ?)', row)
        db.conn.commit()
        return REGISTERED
    else:
        return USER_EXISTS


def get_user_friends():
    val = db.cursor.execute('SELECT username FROM users').fetchall()
    return val


def handle_call_request(request_author, request_receiver):
    receiver_is_online = request_receiver in connected_users
    if receiver_is_online:
        receiver_conn = connected_users.get(request_receiver)
        msg = '!CALL_REQUEST$$$' + str(request_author)
        encoded_msg = bytes(msg, 'utf-8')
        receiver_conn.send(encrypt_message(receiver_conn, msg))
    else:
        author_conn = connected_users.get(request_author)
        msg = '!CALL_REQUEST_REFUSED$$$' + str(request_receiver)
        author_conn.send(encrypt_message(author_conn, msg))


def start():
    sock.listen()
    while True:
        connection, address = sock.accept()
        thread = threading.Thread(target=handle_client_requests, args=(connection, address))
        thread.start()
        print(f"[ACTIVE CLIENTS] {threading.activeCount() - 1} CLIENT IP:PORT: {address}")


# Server starts here

print("Server is starting...")
key = RSA.generate(2048)
public = key.public_key().exportKey()
private = key.exportKey()
print('Server generated public key: ' + str(public))
print('Server generated private key: ...')
start()
print("Server is now running\n")

stream.close()
pa.terminate()
