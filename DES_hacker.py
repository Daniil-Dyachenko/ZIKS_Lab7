import time
import itertools

from DES_Chipher import (
    generate_round_keys,
    process_block,
    hex_to_text,
    encrypt_message,
    decrypt_message
)


def brute_force_attack(cipher_hex, known_text_part, known_key_part, missing_chars=2):

    print(f"\nПочаток brute-force атаки.")
    print(f"Відома частина ключа: {known_key_part}")
    print(f"Невідомих HEX-символів: {missing_chars}")
    print(f"Шукаємо текст, що містить: '{known_text_part}'")

    hex_charset = "0123456789ABCDEF"
    combinations = itertools.product(hex_charset, repeat=missing_chars)

    start_time = time.time()
    attempts = 0

    for combo in combinations:
        attempts += 1
        guess_key = known_key_part + "".join(combo)

        first_block = cipher_hex[:16]
        rkb = generate_round_keys(guess_key)
        rkb_rev = rkb[::-1]

        decrypted_hex_block = process_block(first_block, rkb_rev)
        decrypted_text_block = hex_to_text(decrypted_hex_block)

        if known_text_part in decrypted_text_block:
            elapsed_time = time.time() - start_time
            print(f"\nВЗЛАМ УСПІШНИЙ!")
            print(f"Знайдений ключ: {guess_key}")
            print(f"Кількість спроб перебору: {attempts}")
            print(f"Витрачено часу: {elapsed_time:.4f} секунд\n")

            full_decrypted_text = decrypt_message(cipher_hex, guess_key)
            print("РОЗШИФРОВАНИЙ ТЕКСТ:")
            print(full_decrypted_text)

            return guess_key, elapsed_time

    print("Ключ не знайдено.")
    return None, time.time() - start_time


if __name__ == "__main__":
    # 128 байтів
    #email_message = (
        #"Тема: Звіт\n"
        #"Сервер бази даних працює стабільно. Помилок немає. Код: 200 OK. "
    #)
    # 512 байтів
    #email_message = (
        #"Тема: Оновлення доступу\n"
        #"Шановні колеги! Повідомляємо про зміну правил доступу до нашої серверної "
        #"інфраструктури. Відтепер усі підключення по SSH можливі виключно через "
        #"корпоративний VPN з використанням 2FA. Старі ключі доступу буде "
        #"деактивовано завтра. Будь ласка, згенеруйте нові.  "
    #)
    # 1024 байтів
    #email_message = (
        #"Тема: Результати розслідування інциденту безпеки\n"
        #"Кому: Рада директорів\n\n"
        #"Цей звіт містить детальний аналіз несанкціонованого доступу до нашої мережі. "
        #"Атакуючі використали вразливість у застарілому плагіні веб-порталу для "
        #"завантаження веб-шелу. Після отримання первинного доступу, зловмисники "
        #"підвищили привілеї та спробували вивантажити таблиці бази даних з хешами паролів.\n"
        #"Завдяки оперативному реагуванню, активність заблоковано на етапі ексфільтрації. "
        #"Жоден клієнтський пароль не був скомпрометований. Ми вимагаємо від співробітників "
       # "змінити дані.    "
    #)


    email_message = """Тема: КОНФІДЕНЦІЙНО. Звіт про вразливості системи.
    Від кого: Адміністратор безпеки
    Кому: Головний інженер

    Увага! Під час перевірки мережевого периметра було виявлено критичну вразливість нульового дня (0-day) у модулі авторизації. Зловмисники можуть отримати несанкціонований доступ до бази даних клієнтів.
    Необхідно терміново застосувати патч безпеки №4092.
    Пароль для розпакування архіву з патчем: P@ssw0rd_Secur3!
    
    Прочитати та негайно видалити цей лист."""

    secret_key = "133457799BBCDFF1"

    msg_size_bytes = len(email_message.encode('utf-8'))
    print(f"Розмір перехопленого повідомлення: {msg_size_bytes} байтів")
    encrypted_msg = encrypt_message(email_message, secret_key)
    print(f"Перехоплений шифротекст: {encrypted_msg}")

    known_header = "Тема"

    missing = 3
    known_key_part = secret_key[:-missing]

    hack_des_key, hack_time = brute_force_attack(encrypted_msg, known_header, known_key_part, missing)