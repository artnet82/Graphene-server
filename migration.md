cd ~/Graphen-server/Graphene-server

# 1) Однократно: инициализировать Alembic
flask --app app db init

# 2) Сгенерировать первую миграцию из текущих моделей
flask --app app db migrate -m "initial schema"

# 3) Если БД УЖЕ существует (у вас есть данные) — пометить её как актуальную:
flask --app app db stamp head

# 4) Если БД пустая (fresh install) — применить миграцию:
# flask --app app db upgrade

flask --app app db current
# → should output: <revision> (head)

flask --app app db migrate -m "add field X"
flask --app app db upgrade