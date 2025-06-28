import bcrypt

def hash_password(password: str) -> str:
    """
    Хеширует пароль с использованием bcrypt.
    
    :param password: Пароль в виде строки.
    :return: Хешированный пароль в виде строки.
    """
    # Генерируем соль (salt) и хешируем пароль
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def check_password(password: str, hashed_password: str) -> bool:
    """
    Проверяет, соответствует ли пароль хешированному паролю.
    
    :param password: Пароль в виде строки.
    :param hashed_password: Хешированный пароль в виде строки.
    :return: True, если пароль верный, иначе False.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

if __name__ == "__main__":
    # Запрашиваем пароль у пользователя
    password = input("Введите пароль для хеширования: ").strip()
    
    if not password:
        print("Ошибка: пароль не может быть пустым!")
        exit(1)
    
    # Хешируем пароль
    hashed = hash_password(password)
    print(f"\nХешированный пароль: {hashed}")

