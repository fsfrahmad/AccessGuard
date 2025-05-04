from http import client
from mailbox import Message
from RSA import RSACredentialManager
import AES, getpass
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

### RSA Encryption/Decryption Configuration for User Credentials

manager = RSACredentialManager()

def Generate_RSA_Keys():
    manager.generate_keys()
    manager.save_private_key("private_key.pem", password="LP-Gangster")
    manager.save_public_key("public_key.pem")

def Encrypt_Credentials(ID, Username, Email, Password, OTP, Role, Verified, Status, MongoDB_Connection_String):
    client = MongoClient(MongoDB_Connection_String)
    manager.load_public_key("public_key.pem")
    Encrypted_Username, Encrypted_Email, Encrypted_Password, Encrypted_OTP = manager.encrypt_credentials(Username, Email, Password, OTP)
    if Status == "New":
        client["Users"]["Login Credentials"].insert_one({"Username":Encrypted_Username,"Email":Encrypted_Email, "Password":Encrypted_Password, "OTP":Encrypted_OTP, "Role":Role, "Verified":Verified})
    elif Status == "Existing":
        client["Users"]["Login Credentials"].replace_one({"_id":ID}, {"_id":ID, "Username":Encrypted_Username, "Email":Encrypted_Email, "Password":Encrypted_Password, "OTP":Encrypted_OTP, "Role":Role, "Verified":Verified})
    client.close()

def Decrypt_Credentials(Username, Email, Password, OTP, Status, MongoDB_Connection_String):
    User_Found = False
    client = MongoClient(MongoDB_Connection_String)
    manager.load_private_key("private_key.pem", "LP-Gangster")
    Credentials = client["Users"]["Login Credentials"].find({}, {"Username": 1, "Email": 1, "Password": 1, "OTP": 1, "_id": 1})
    Encrypted_Credentials = []
    for User in Credentials:
        Encrypted_Credentials.append({"Username": User["Username"], "Email":User["Email"], "Password": User["Password"], "OTP":User["OTP"], "ID":User["_id"]})
    for User in Encrypted_Credentials:
        Decrypted_Username, Decrypted_Email, Decrypted_Password, Decrypted_OTP = manager.decrypt_credentials(User["Username"], User["Email"], User["Password"], User["OTP"])
        if Status == "Validate":
            if (Username == Decrypted_Username or Email == Decrypted_Email) and Password == Decrypted_Password:
                User_Found = True
                return User_Found
        elif Status == "Get_OTP_And_ID":
            if Username == Decrypted_Username or Email == Decrypted_Email:
                return User["ID"], Decrypted_Username, Decrypted_Email, Decrypted_OTP
    return User_Found
    client.close()

### AES Encryption/Decryption Configuration for Chat Access Records

def Search_Encrypted_Chat_Records(User_01_ID, User_02_ID,MongoDB_Connection_String):
    Chat_Found = False
    client = MongoClient(MongoDB_Connection_String)
    Chat_Users = client["Chats"]["Encrypted_Chat_Records"].find_one({"User_01_ID": User_01_ID, "User_02_ID": User_02_ID}, {"_id":1, "Chat Access Key":1, "Chat Access Salt":1})
    if not Chat_Users:
        return Chat_Found, None, None, None
    else:
        Chat_Found = True
        return Chat_Found, Chat_Users["_id"], Chat_Users["Chat Access Key"], Chat_Users["Chat Access Salt"]
    client.close()

def Encrypt_Chat(ID, User_01_ID, User_02_ID, User_01, User_02, Key, Salt, Status, MongoDB_Connection_String):
    client = MongoClient(MongoDB_Connection_String)
    if Status == "New":
        manager.load_public_key("public_key.pem")
        Encrypted_Key = manager.encrypt_aes_key(Key)
        Key, Salt = AES.generate_aes_key(Key)
        Encrypted_User_01_Message = AES.encrypt_message(User_01, Key)
        Encrypted_User_02_Message = AES.encrypt_message(User_02, Key)
        client["Chats"]["Encrypted_Chat_Records"].insert_one({"Chat Access Key":Encrypted_Key, "Chat Access Salt":Salt, "User_01_ID":User_01_ID, "User_02_ID":User_02_ID, "User_01":[Encrypted_User_01_Message], "User_02":[Encrypted_User_02_Message]})
    elif Status == "Existing":
        manager.load_private_key("private_key.pem", "LP-Gangster")
        Decrypted_Key = manager.decrypt_aes_key(Key)
        Key, Salt = AES.generate_aes_key(Decrypted_Key, Salt)
        Encrypted_User_01_Message = AES.encrypt_message(User_01, Key)
        Encrypted_User_02_Message = AES.encrypt_message(User_02, Key)
        client["Chats"]["Encrypted_Chat_Records"].update_one({"_id": ID}, {"$push": {"User_01": Encrypted_User_01_Message, "User_02": Encrypted_User_02_Message}})
    client.close()

def Decrypt_Chat(ID, MongoDB_Connection_String):
    client = MongoClient(MongoDB_Connection_String)
    manager.load_private_key("private_key.pem", "LP-Gangster")
    Chat_Records = client["Chats"]["Encrypted_Chat_Records"].find({"_id": ID}, {"Chat Access Key":1, "Chat Access Salt":1, "User_01":1, "User_02":1, "_id":0})
    Decrypted_User_01_Message = []
    Decrypted_User_02_Message = []
    for Chat in Chat_Records:
        Decrypted_Key = manager.decrypt_aes_key(Chat["Chat Access Key"])
        Key, Salt= AES.generate_aes_key(Decrypted_Key, Chat["Chat Access Salt"])
        for Message in Chat["User_01"]:
            Decrypted_User_01_Message.append(AES.decrypt_message(Message, Key))
        for Message in Chat["User_02"]:
            Decrypted_User_02_Message.append(AES.decrypt_message(Message, Key))
        return Decrypted_User_01_Message, Decrypted_User_02_Message
    client.close()
    
    ##### Must do: Add verify & Role attribute to Users