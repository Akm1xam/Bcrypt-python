# Bcrypt Password Hasher 🔒

Простой и безопасный инструмент для хеширования и проверки паролей с использованием алгоритма bcrypt.

## 📝 Описание

Этот Python-скрипт предоставляет две основные функции:
1. `hash_password` — хеширует пароль с добавлением "соли" (salt) для повышенной безопасности.
2. `check_password` — проверяет, соответствует ли введённый пароль хешированному значению.

Идеально подходит для:
- Систем аутентификации
- Безопасного хранения паролей в базах данных
- Образовательных целей (изучение основ криптографии)

## ⚙️ Установка

1. Убедитесь, что у вас установлен Python 3.6+.
2. Установите необходимую зависимость:
   ```bash
   pip install bcrypt
   ```

## 🚀 Использование

### Хеширование пароля
```python
from Bcrypt import hash_password

hashed = hash_password("ваш_пароль")
print(hashed)  # Вывод: хешированный пароль (например: $2b$12$...)
```

### Проверка пароля
```python
from Bcrypt import check_password

is_valid = check_password("ваш_пароль", hashed_password)
print(is_valid)  # Вывод: True или False
```

### Запуск из командной строки
```bash
python Bcrypt.py
```
(После запуска введите пароль для хеширования)

## 🔒 Особенности безопасности
- Использует алгоритм bcrypt (один из самых надёжных для хеширования паролей)
- Автоматическая генерация "соли" (salt) для каждого пароля
- Защита от атак перебора (brute-force) благодаря медленному хешированию
- Корректная обработка Unicode-паролей


---

> **Примечание:** Никогда не храните пароли в открытом виде! Всегда используйте хеширование.

