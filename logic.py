import tkinter.ttk
from datetime import datetime
import client
from tkinter import *
import threading
import center_tk_window
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

logged_as = ''
public_key_server = ''
exit_thread_flag = False
call_with = ''

key = RSA.generate(2048)
public = key.public_key().exportKey()
private = key.exportKey()


def get_key():
    return private_key_str


def encrypt_data(data):
    pub_key = RSA.importKey(public_key_server)
    encryptor = PKCS1_OAEP.new(pub_key)
    return encryptor.encrypt(data)


def decrypt_data(data):
    decryptor = PKCS1_OAEP.new(key)
    data = decryptor.decrypt(data)
    return data.decode()


def client_is_online():
    global public_key_server
    client.s.send(public)
    response = client.s.recv(4096)
    public_key_server = response


def login_request(login, password):
    global logged_as, public_key_str, private_key_str
    data = '!LOGIN$$$'
    data = data + login + "$$$" + password
    encoded_data = data.encode()
    encrypted_data = encrypt_data(encoded_data)
    client.s.send(encrypted_data)
    response = client.s.recv(4096)
    response = decrypt_data(response)
    response = response.split('$$$')
    if '!LOGGED_IN' == response[0]:
        logged_as = response[1]
        private_key_str = response[2]
        return True
    elif '!ALREADY_LOGGED' == response[0]:
        return -1
    else:
        return False


def register_request(login, password):
    data = '!REGISTER$$$'
    data = data + login + "$$$" + password
    encoded_data = data.encode()
    encrypted_data = encrypt_data(encoded_data)
    client.s.send(encrypted_data)
    response = client.s.recv(4096)
    response = decrypt_data(response)
    if response == '!REGISTERED':
        return True
    else:
        return False


def send_speak_data(data):
    client.s.send(bytearray(data))


def receive_conversation_messages():
    while True:
        data = client.s.recv(1024)
        data = decrypt_data(data)
        client.stream.write(data)


accept_button_clicked = False
decline_button_clicked = False


def accept_call_request(popup):
    global accept_button_clicked, call_with
    popup.destroy()
    accept_button_clicked = True
    conversation_page = main.get_frame(Conversation)
    conversation_page.refresh(call_with)
    main.show_frame(Conversation)


def decline_call_request(popup):
    global decline_button_clicked
    popup.destroy()
    decline_button_clicked = True


call_start_time = 0
call_end_time = 0

exit_event = threading.Event()


def listen_incoming_calls():
    global exit_event
    global accept_button_clicked, decline_button_clicked, key, call_start_time, call_end_time, logged_as, private_key_str
    global exit_thread_flag
    global call_with, is_audio_message

    lobby_frame = main.frames[LobbyPage]
    x = main.winfo_rootx()
    y = main.winfo_rooty()
    #geom = "+%d+%d" % (x, y)
    while True:
        if logged_as != '':
            data = client.s.recv(1024)
            is_audio_message = False
            try:
                decryptor = PKCS1_OAEP.new(key)
                decryptor.decrypt(data)
            except ValueError:
                is_audio_message = True
            if is_audio_message is True:
                client.stream.write(data)
            else:
                decryptor = PKCS1_OAEP.new(key)
                data = decryptor.decrypt(data)
                data = data.decode()
                msg_arr = data.split('$$$')
                if True:
                    dd = data.split('$$$')
                    if dd[0] == '!LOGGED_IN':
                        logged_as = dd[1]
                        private_key_str = dd[2]
                        main.show_frame(LobbyPage)
                    elif dd[0] == '!CALL_REQUEST':
                        call_with = dd[1]
                        popup = Toplevel(lobby_frame)
                        x = main.winfo_rootx()
                        y = main.winfo_rooty()
                        geom = "+%d+%d" % (x, y)
                        popup.geometry(geom)
                        popup.title("Połączenie przychodzące")
                        popup.geometry("300x100")
                        popup.configure(bg="grey19")
                        button_accept = Button(popup, text="Akceptuj", command=lambda: accept_call_request(popup),
                                               bg="forest green", fg='Black',
                                               font=('calibri', 10, 'bold'), pady=5, padx=5)
                        button_accept.grid(row=1, column=0)
                        button_accept.place()

                        button_decline = Button(popup, text="Odrzuć", command=lambda: decline_call_request(popup),
                                                bg="firebrick2", fg='Black',
                                                font=('calibri', 10, 'bold'), pady=5, padx=5)
                        button_decline.grid(row=1, column=0, sticky=E)
                        button_decline.place()

                        info_label = Label(popup, text="Połączenie przychodzące od " + dd[1], bg="gray19", fg='White',
                                           font=('Century Gothic', 10), pady=5,
                                           padx=5)
                        info_label.grid(row=0)
                        info_label.place()

                        while accept_button_clicked is False and decline_button_clicked is False:
                            if accept_button_clicked:
                                msg = data + '$$$ACCEPT$$$' + logged_as
                                encoded_data = msg.encode()
                                call_with = dd[1]
                                conversation_frame = main.get_frame(Conversation)
                                conversation_frame.refresh(dd[1])
                                encrypted_data = encrypt_data(encoded_data)
                                client.s.send(encrypted_data)
                                accept_button_clicked = False
                                break

                            elif decline_button_clicked:
                                msg = data + '$$$DECLINE$$$' + logged_as
                                encoded_data = msg.encode()
                                encrypted_data = encrypt_data(encoded_data)
                                client.s.send(encrypted_data)
                                decline_button_clicked = False
                                break

                    elif dd[0] == '!CALL_REQUEST_ACC' and dd[1] == 'ACCEPTANCE':
                        main.show_frame(Conversation)  # dla odbiorcy - akceptujący połączenie przychodzące
                        call_with = dd[2]
                        call_start_time = datetime.now()
                    elif dd[0] == '!CALL_REQUEST_DCC':
                        popup_call_refused = Toplevel(lobby_frame)
                        x = main.winfo_rootx()
                        y = main.winfo_rooty()
                        geom = "+%d+%d" % (x, y)
                        popup_call_refused.geometry(geom)
                        popup_call_refused.title("Komunikat")
                        popup_call_refused.geometry("300x50")
                        popup_call_refused.configure(bg="grey19")
                        popup_call_end_info = Label(popup_call_refused,
                                                    text="Użytkownik nie odebrał od Ciebie połączenia",
                                                    bg="gray19",
                                                    fg='White', font=('Century Gothic', 10), pady=5,
                                                    padx=5)
                        popup_call_end_info.pack()
                    elif dd[0] == '!CALL_END':
                        call_end_time = datetime.now()
                        msg = data + '$$$CONVERSATION_SAVE$$$' + str(call_start_time) + '$$$' + str(
                            call_end_time) + "$$$" + logged_as
                        encoded_data = msg.encode()
                        encrypted_data = encrypt_data(encoded_data)
                        if logged_as == dd[1]:
                            main.show_frame(LobbyPage)
                            lobby_frame = main.frames[LobbyPage]
                            popup_call_end = Toplevel(lobby_frame)
                            x = main.winfo_rootx()
                            y = main.winfo_rooty()
                            geom = "+%d+%d" % (x, y)
                            popup_call_end.geometry(geom)
                            popup_call_end.title("Komunikat")
                            popup_call_end.geometry("300x50")
                            popup_call_end.configure(bg="grey19")
                            popup_call_end_info = Label(popup_call_end, text="Rozmowa została zakończona", bg="gray19",
                                                        fg='White', font=('Century Gothic', 10), pady=5,
                                                        padx=5)
                            popup_call_end_info.pack()
                            client.s.send(encrypted_data)
                        else:
                            msg = '!CALL_END$$$' + logged_as
                            encoded_data = msg.encode()
                            encrypted_data = encrypt_data(encoded_data)
                            client.s.send(encrypted_data)

                            main.show_frame(LobbyPage)
                            lobby_frame = main.frames[LobbyPage]

                            popup_call_end = Toplevel(lobby_frame)
                            x = main.winfo_rootx()
                            y = main.winfo_rooty()
                            geom = "+%d+%d" % (x, y)
                            popup_call_end.geometry(geom)
                            popup_call_end.title("Komunikat")
                            popup_call_end.geometry("300x50")
                            popup_call_end.configure(bg="grey19")
                            popup_call_end_info = Label(popup_call_end, text="Rozmowa została zakończona", bg="gray19",
                                                        fg='White', font=('Century Gothic', 10), pady=5,
                                                        padx=5)
                            popup_call_end_info.pack()
                    elif dd[0] == '!GET_HISTORY':
                        history_calls = []
                        if msg_arr[1] == 'NO_HISTORY':
                            return 0
                        else:
                            for a in msg_arr:
                                a_list = list(a.split(", "))
                                history_calls.append(a_list)

                        lobby_frame = main.frames[LobbyPage]
                        lobby_frame.get_call_history(history_calls)
                    elif dd[0] == '!CALL_REQUEST_REFUSED':
                        popup_call_no_online = Toplevel(lobby_frame)
                        x = main.winfo_rootx()
                        y = main.winfo_rooty()
                        geom = "+%d+%d" % (x, y)
                        popup_call_no_online.geometry(geom)
                        popup_call_no_online.title("Komunikat")
                        popup_call_no_online.geometry("300x50")
                        popup_call_no_online.configure(bg="grey19")
                        popup_call_end_info = Label(popup_call_no_online, text="Użytkownik nie jest aktualnie dostępny",
                                                    bg="gray19",
                                                    fg='White', font=('Century Gothic', 10), pady=5,
                                                    padx=5)
                        popup_call_end_info.pack()
                        # lobby_frame.destroy_element("make_call_popup")
                    elif dd[0] == '!LOGOUT':
                        logged_as = ''
        else:
            break
    print("METHOD LOOP THREAD IS END")


def get_user_friends():
    global logged_as
    data = '!GET_FRIENDS$$$'
    data = data + logged_as
    encoded_data = data.encode()
    encrypted_data = encrypt_data(encoded_data)
    client.s.send(encrypted_data)
    response = client.s.recv(4096)
    response = decrypt_data(response)
    response = response.split('@')
    friends = []
    for a in response:
        if len(a) > 0 and a[0] != '!':
            friends.append(a)
    return friends


def get_call_history_logic():
    global logged_as
    data = '!GET_HISTORY$$$' + str(logged_as)
    encoded_data = data.encode()
    encrypted_data = encrypt_data(encoded_data)
    client.s.send(encrypted_data)
    response = client.s.recv(4096)
    response = decrypt_data(response)
    response = response.split('$$$')
    history_calls = []
    if response[1] == '!NO_HISTORY':
        return 0
    else:
        for a in response:
            a_list = list(a.split(", "))
            history_calls.append(a_list)
        return history_calls


def make_call(username):
    global call_with
    call_with = username
    msg = '!MAKE_CALL$$$' + '@' + str(logged_as) + '@' + str(username)
    encoded_data = msg.encode()
    encrypted_data = encrypt_data(encoded_data)
    client.s.send(encrypted_data)


def logout_request():
    global logged_as, exit_thread_flag, thread
    msg = '!LOGOUT$$$' + str(logged_as)
    encoded_data = msg.encode()
    encrypted_data = encrypt_data(encoded_data)
    logged_as = ''
    exit_thread_flag = True
    client.s.send(encrypted_data)


def run():
    print("Client is running...")


def handle_call_end():
    msg = '!CALL_END$$$' + str(logged_as)
    encoded_data = msg.encode()
    encrypted_data = encrypt_data(encoded_data)
    client.s.send(encrypted_data)


def refresh_history_call():
    global logged_as
    data = '!REFRESH_HISTORY$$$' + str(logged_as)
    encoded_data = data.encode()
    encrypted_data = encrypt_data(encoded_data)
    client.s.send(encrypted_data)


###########
### GUI ###
##########


class gui(Tk):
    def __init__(self, *args, **kwargs):
        Tk.__init__(self, *args, **kwargs)

        container = Frame(self)
        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        client_is_online()

        for F in (StartPage, LoginPage, RegisterPage, LobbyPage, Conversation):
            frame = F(container, self)
            frame.configure(bg='gray19')
            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)

    def show_frame(self, cont):
        if cont == LobbyPage:
            thread = threading.Thread(target=listen_incoming_calls)
            thread.start()
            print("thread in show frame called")
        frame = self.frames[cont]
        frame.tkraise()

    def get_frame(self, frame_class):
        return self.frames[frame_class]


class StartPage(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = Label(self, text="Komunikator", bg="gray19", fg='White', font=('Century Gothic', 30, 'bold'), pady=5,
                      padx=5)
        label.grid(row=0, column=0, padx=10, pady=10)
        label.place(relx=0.5, rely=0.1, anchor='center')
        button1 = Button(self, text="Zaloguj się",
                         command=lambda: controller.show_frame(LoginPage), bg="grey62", fg='Black',
                         font=('calibri', 15, 'bold'), pady=5, padx=5)
        button1.grid(row=1, column=0, padx=10, pady=15)
        button1.place(relx=0.5, rely=0.25, anchor='center')
        button2 = Button(self, text="Zarejestruj się",
                         command=lambda: controller.show_frame(RegisterPage), bg="grey62", fg='Black',
                         font=('calibri', 15, 'bold'), pady=5)
        button2.grid(row=2, column=0, padx=10, pady=15)
        button2.place(relx=0.5, rely=0.4, anchor='center')


class LoginPage(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        label = Label(self, text="Logowanie", bg="gray19", fg='White', font=('Century Gothic', 15, 'bold'), pady=5)
        label.grid(row=0, column=1, padx=10, pady=10)

        self.controller = controller

        login_var = StringVar()
        password_var = StringVar()
        Label(self, text="Login", bg="gray19", fg='White', font=('calibri', 12), pady=5).grid(row=1, column=0,
                                                                                              padx=(220, 5), sticky=E)
        login_input = Entry(self, textvariable=login_var, width=30)
        login_input.grid(row=1, column=1, sticky=W)
        Label(self, text="Hasło", bg="gray19", fg='White', font=('calibri', 12), pady=5).grid(row=2, column=0,
                                                                                              padx=(220, 5), sticky=E)
        password_input = Entry(self, textvariable=password_var, show='*', width=30)
        password_input.grid(row=2, column=1, sticky=W)

        button1 = Button(self, text="Powrót",
                         command=lambda: controller.show_frame(StartPage), bg="grey62", fg='Black',
                         font=('calibri', 10, 'bold'), pady=5)
        button1.grid(row=3, column=1, padx=10, pady=10, sticky=E)

        def login_btn_funcs():
            global logged_as, exit_thread_flag
            if logged_as == '':
                get_login_data()
                lobby_frame = self.controller.get_frame(LobbyPage)
                lobby_frame.create_contact_list_label()
                lobby_frame.create_call_buttons()
                lobby_frame.set_welcome_label()

        def get_login_data():
            if login_var.get() != '' and password_var.get() != '':
                response = login_request(login_var.get(), password_var.get())
                if response == True:
                    login_input.delete(0, "end")
                    login_input.insert(0, '')
                    password_input.delete(0, "end")
                    password_input.insert(0, '')
                    controller.show_frame(LobbyPage)
                elif response == False:
                    wrong_creds_popup = Toplevel(self)
                    x = main.winfo_rootx()
                    y = main.winfo_rooty()
                    geom = "+%d+%d" % (x, y)
                    wrong_creds_popup.geometry(geom)
                    wrong_creds_popup.title("Błąd logowania")
                    wrong_creds_popup.configure(bg="grey19")

                    popup_info = Label(wrong_creds_popup, text="Podano nieprawidłowe hasło lub użytkownik nie istnieje",
                                       bg="gray19", fg='White', font=('Century Gothic', 10), pady=5)
                    popup_info.pack()
                    center_tk_window.center(parent, wrong_creds_popup)
                elif response == -1:
                    wrong_creds_popup = Toplevel(self)
                    x = main.winfo_rootx()
                    y = main.winfo_rooty()
                    geom = "+%d+%d" % (x, y)
                    wrong_creds_popup.geometry(geom)
                    wrong_creds_popup.title("Błąd logowania")
                    wrong_creds_popup.configure(bg="grey19")
                    wrong_creds_popup.geometry("300x50")
                    popup_info = Label(wrong_creds_popup, text="Wskazany użytkownik jest już zalogowany", bg="gray19",
                                       fg='White', font=('Century Gothic', 10), pady=5)
                    popup_info.pack()
                    center_tk_window.center(parent, wrong_creds_popup)
            else:
                empty_fields_popup = Toplevel(self)
                x = main.winfo_rootx()
                y = main.winfo_rooty()
                geom = "+%d+%d" % (x, y)
                empty_fields_popup.geometry(geom)
                empty_fields_popup.title("Błąd logowania")
                empty_fields_popup.configure(bg="grey19")
                empty_fields_popup.geometry("300x50")
                popup_info = Label(empty_fields_popup, text="Należy uzupełnić wszystkie pola", bg="gray19", fg='White',
                                   font=('Century Gothic', 10), pady=5)
                popup_info.pack()
                center_tk_window.center(parent, empty_fields_popup)

        button2 = Button(self, text="Zaloguj się", command=login_btn_funcs, bg="grey62", fg='Black',
                         font=('calibri', 10, 'bold'), pady=5)
        button2.grid(row=3, column=1, padx=10, pady=10, sticky=W)


class RegisterPage(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        login_var = StringVar()
        password_var = StringVar()
        re_password_var = StringVar()

        Label(self, text="Login", bg="gray19", fg='White', font=('calibri', 12), pady=5).grid(row=1, column=0, sticky=E,
                                                                                              padx=(180, 5))
        login_input = Entry(self, textvariable=login_var, width=30)
        login_input.grid(row=1, column=1, sticky=W)
        Label(self, text="Hasło", bg="gray19", fg='White', font=('calibri', 12), pady=5).grid(row=2, column=0, sticky=E,
                                                                                              padx=(180, 5))
        password_input = Entry(self, textvariable=password_var, show='*', width=30)
        password_input.grid(row=2, column=1, sticky=W)
        Label(self, text="Powtórz hasło", bg="gray19", fg='White', font=('calibri', 12), pady=5).grid(row=3, column=0,
                                                                                                      sticky=E,
                                                                                                      padx=(180, 5))
        re_password_input = Entry(self, textvariable=re_password_var, show='*', width=30)
        re_password_input.grid(row=3, column=1, sticky=W)

        def get_register_data():
            if login_var.get() != '' and password_var.get() != '' and re_password_var.get() != '':
                if password_var.get() != re_password_var.get():
                    wrong_repassword_popup = Toplevel(self)
                    x = main.winfo_rootx()
                    y = main.winfo_rooty()
                    geom = "+%d+%d" % (x, y)
                    wrong_repassword_popup.geometry(geom)
                    wrong_repassword_popup.title("Błąd rejestracji")
                    wrong_repassword_popup.geometry("300x50")
                    wrong_repassword_popup.configure(bg="grey19")
                    popup_info = Label(wrong_repassword_popup, text="Podane hasła nie są takie same", bg="gray19",
                                       fg='White', font=('Century Gothic', 10), pady=5)
                    popup_info.pack()
                else:
                    if register_request(login_var.get(), password_var.get()):
                        controller.show_frame(StartPage)
                        user_exists_popup = Toplevel(self)
                        x = main.winfo_rootx()
                        y = main.winfo_rooty()
                        geom = "+%d+%d" % (x, y)
                        user_exists_popup.geometry(geom)
                        user_exists_popup.title("Rejestracja pomyślna")
                        user_exists_popup.geometry("300x50")
                        user_exists_popup.configure(bg="grey19")
                        popup_info = Label(user_exists_popup, text="Konto zostało zarejestrowane", bg="gray19",
                                           fg='White', font=('Century Gothic', 10), pady=5)
                        popup_info.pack()
                        login_input.delete(0, "end")
                        login_input.insert(0, '')
                        password_input.delete(0, "end")
                        password_input.insert(0, '')
                        re_password_input.delete(0, "end")
                        re_password_input.insert(0, '')
                    else:
                        user_exists_popup = Toplevel(self)
                        x = main.winfo_rootx()
                        y = main.winfo_rooty()
                        geom = "+%d+%d" % (x, y)
                        user_exists_popup.geometry(geom)
                        user_exists_popup.title("Błąd rejestracji")
                        user_exists_popup.geometry("300x50")
                        user_exists_popup.configure(bg="grey19")
                        popup_info = Label(user_exists_popup, text="Wskazany użytkownik już istnieje", bg="gray19",
                                           fg='White', font=('Century Gothic', 10), pady=5)
                        popup_info.pack()
            else:
                empty_fields_popup = Toplevel(self)
                x = main.winfo_rootx()
                y = main.winfo_rooty()
                geom = "+%d+%d" % (x, y)
                empty_fields_popup.geometry(geom)
                empty_fields_popup.title("Błąd rejestracji")
                empty_fields_popup.geometry("300x50")
                empty_fields_popup.configure(bg="grey19")
                popup_info = Label(empty_fields_popup, text="Należy uzupełnić wszystkie pola", bg="gray19", fg='White',
                                   font=('Century Gothic', 10), pady=5)
                popup_info.pack()

        label = Label(self, text="Rejestracja konta", bg="gray19", fg='White', font=('calibri', 15, 'bold'), pady=5)
        label.grid(row=0, column=1, padx=10, pady=10, sticky=W)
        button2 = Button(self, text="Powrót", command=lambda: controller.show_frame(StartPage), bg="grey62", fg='Black',
                         font=('calibri', 10, 'bold'), pady=5)
        button2.grid(row=4, column=1, padx=3, pady=10, sticky=E)
        button3 = Button(self, text="Zarejestruj się", command=get_register_data, bg="grey62", fg='Black',
                         font=('calibri', 10, 'bold'), pady=5)
        button3.grid(row=4, column=1, padx=3, pady=10, sticky=W)


class LobbyPage(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        self.welcome_text = StringVar()
        label = Label(self, textvariable=self.welcome_text, bg="gray19", fg='White', font=('Century Gothic', 10),
                      pady=5, width=50)
        label.grid(row=0, column=1, padx=10, pady=10)

        def logout_button_funcs():
            controller.show_frame(StartPage)
            logout_request()

        button1 = Button(self, text="Wyloguj się", command=logout_button_funcs, bg="grey62", fg='Black',
                         font=('calibri', 12, 'bold'), pady=5, padx=5)
        button1.grid(row=1, column=1, padx=10, pady=10)


        self.my_tree = tkinter.ttk.Treeview(self)
        self.my_tree['columns'] = ['Rozmowa z', 'Data', 'Godzina', 'Czas trwania']

        self.my_tree.column('#0', width=0, stretch=NO)
        self.my_tree.column("Rozmowa z", anchor=CENTER, width=75)
        self.my_tree.column("Data", anchor=CENTER, width=75)
        self.my_tree.column("Godzina", anchor=CENTER, width=90)
        self.my_tree.column("Czas trwania", anchor=CENTER, width=75)

        self.my_tree.heading("#0", text="", anchor=CENTER)
        self.my_tree.heading("Rozmowa z", text="Rozmowa z", anchor=CENTER)
        self.my_tree.heading("Data", text="Data", anchor=CENTER)
        self.my_tree.heading("Godzina", text="Godzina rozp.", anchor=CENTER)
        self.my_tree.heading("Czas trwania", text="Czas trwania", anchor=CENTER)

        self.my_tree.insert(parent='', index='end', iid=0, text='', values=('user3', '14.06.2021', '13:04', '00:12:43'))
        self.my_tree.grid(row=2, column=1, sticky=W, padx=10)

    def destroy_element(self, name):
        pass

    def get_call_history(self, history):
        username = ''
        self.my_tree.delete(*self.my_tree.get_children())
        if history != 0:
            history = history[1:-1]
            if history != 0:
                i = 0
                for a in history:
                    if a != ['!GET_HISTORY'] or a != ['']:
                        if a[1].replace("'", '') == logged_as:
                            username = a[2].replace("'", '')
                        else:
                            username = a[1].replace("'", '')
                        self.my_tree.insert(parent='', index='end', iid=i, text='',
                                            values=(username, a[3].replace("'", ''), a[4].replace("'", ''),
                                                    a[5].replace("'", '').replace(")", '')))
                        i += 1

    def start_receiving(self):
        thread = threading.Thread(target=receive_conversation_messages, args=())
        thread.start()

    def button2_fun(self):
        self.controller.show_frame(Conversation)
        self.start_receiving()

    def make_call(self, user):
        make_call(user)
        make_call_popup = Toplevel(self)
        x = main.winfo_rootx()
        y = main.winfo_rooty()
        geom = "+%d+%d" % (x, y)
        make_call_popup.geometry(geom)
        make_call_popup.title("Trwa nawiązywanie rozmowy...")
        make_call_popup.geometry("300x50")
        make_call_popup.configure(bg="grey19")
        make_call_popup = Label(make_call_popup, text="Trwa nawiązywanie rozmowy....", bg="gray19", fg='White',
                                font=('Century Gothic', 10), pady=5)
        make_call_popup.pack()

    def create_contact_list_label(self):
        contact_list_label = Label(self, text="Lista kontaktów", bg="gray19", fg='White', font=('Century Gothic', 13),
                                   pady=5)
        contact_list_label.grid(row=1, column=2, pady=5, padx=10)

    def create_call_buttons(self):
        friends = get_user_friends()

        container = Frame(self)
        container.grid(row=2, column=2, sticky=N)

        for i in range(len(friends)):
            if friends[i] != logged_as:
                e = Button(container, text=friends[i], command=lambda f=friends[i]: self.make_call(f), bg="grey62",
                           fg='Black', font=('Century Gothic', 10), width=17)
                e.grid(row=i + 1, column=2, pady=1, sticky=N)
        lp = self.controller.get_frame(LobbyPage)
        lp.get_call_history(get_call_history_logic())

    def set_welcome_label(self):
        self.welcome_text.set("Witaj.\nJesteś zalogowany jako " + str(logged_as) + ".")

    def create_call_acceptance_popup(self):
        popup = Toplevel(self)
        popup.title("Połączenie przychodzące")
        x = main.winfo_rootx()
        y = main.winfo_rooty()
        geom = "+%d+%d" % (x, y)
        popup.geometry(geom)
        popup.geometry("300x50")
        popup.configure(bg="grey19")
        popup_info = Label(popup, text="button akceptuj i odrzuć połączenie", bg="gray19", fg='White',
                           font=('Century Gothic', 10), pady=5)
        popup_info.pack()


class Conversation(Frame):
    def __init__(self, parent, controller):
        self.mute = True
        Frame.__init__(self, parent)
        self.mouse_pressed = False
        self.controller = controller
        self.createWidgets()

        def finish_call():
            self.controller.show_frame(LobbyPage)
            handle_call_end()

        self.return_button = Button(self, text="Zakończ rozmowę", command=finish_call, bg="firebrick2", fg='Black',
                                    font=('Century Gothic', 10, 'bold'))
        self.return_button.grid(row=5, column=0, padx=10, pady=10)
        self.return_button.place(relx=0.5, rely=0.2, anchor='center')


    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

    def OnMouseDown(self, event):
        self.mute = False
        # self.mute = True
        self.speakStart()

    def muteSpeak(self, event):
        self.mute = True

    def speakStart(self):
        t = threading.Thread(target=self.speak)
        t.start()

    def speak(self):
        while self.mute is False:
            data = client.stream.read(client.chunk)
            send_speak_data(data)

    def createWidgets(self):
        self.speakb = Button(self, command=self.speakStart, text="Rozmowa", bg="grey62", fg='Black',
                             font=('Century Gothic', 10, 'bold'))
        self.speakb.grid(row=0, column=0, padx=10, pady=10)
        self.speakb.place(relx=0.5, rely=0.1, anchor='center')
        self.speakb.bind("<ButtonPress-1>", self.OnMouseDown)
        self.speakb.bind("<ButtonRelease-1>", self.muteSpeak)

    def refresh(self, username):
        self.call_with_info = Label(self, text="Rozmowa z użytkownikiem " + str(username), bg="gray19", fg='White',
                                    font=('Century Gothic', 10), pady=5)


# if __name__ == "__main__":
main = gui()
main.geometry("700x400")
main.eval('tk::PlaceWindow . center')
main.title("TIP projekt")
main.mainloop()
print("GUI is running....")