cd ~/Graphen-server/Graphene-server

# 1) Установить новые зависимости
pip install -r requirements.txt

# 2) Сгенерировать секреты
export GRAPHENE_SECRET=$(openssl rand -hex 32)
export GRAPHENE_ADMIN_HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('ВАШ_ПАРОЛЬ'))")

# 3) Инициализировать Alembic (один раз)
flask --app app db init
flask --app app db migrate -m "initial schema"

# 4) Если БД УЖЕ существует (ваш случай)
flask --app app db stamp head

# 5) Запустить
python3 app.py