import json


with open('users.json', 'r') as file:
        data = json.load(file)
        users_list = data.get('users', [])  # 'users' anahtarını alıyoruz

usernames = [user['username'] for user in users_list]

print(usernames) 