Palatine Whiteboard (Blocksuite + Yjs)

Запуск

1) Требуется Docker Desktop
2) В корне:
```bash
docker compose up -d --build
```
3) Откройте `http://localhost:3000`

Функции

- Генерация картинки: введите текст и нажмите «Сгенерировать». Бэкенд вернет URL и проксирует изображение.
- Вставка на доску: изображение сохраняется в `page.blob`, блок `affine:image` добавляется на `affine:surface`.
- Сохранение:
  - Инкрементальные апдейты Yjs отправляются в Redis (`/api/sync`).
  - Полный снапшот отправляется раз в ~8с и при закрытии вкладки (`/api/flush`) и сохраняется в Postgres.
  - При старте состояние выгружается с бэка (`/api/load`) или из `localStorage`.

Проверка сохранения

1) Внесите изменения на доске (вставьте картинку).
2) Дождитесь 8–10 секунд или обновите вкладку (при закрытии срабатывает beacon/flush).
3) Проверьте БД:
```bash
docker exec -it palatine-db-1 psql -U palatine -d palatine -c "select user_id, octet_length(ydoc) as size, updated_at from documents order by updated_at desc limit 5;"
```

Переменные/порты

- Frontend: 3000
- Backend: 4000
- Postgres 17: 5432 (user: palatine, password: palatine, db: palatine)
- Redis 7: 6379

API (бэкенд)

- `POST /api/gen-image` { prompt?: string } → { url: string }
- `GET /api/proxy-image?url=...` → image/* (CORS-safe)
- `POST /api/sync` { userId: string, update: number[] }
- `POST /api/flush` { userId: string, snapshot?: number[] }
- `GET /api/load?userId=...` → { update: number[] }

Заметки

- Генерация изображения — заглушка: берём картинку по теме запроса из публичного источника, без гарантий 100% релевантности.
- Для детерминированных картинок можно заменить `/api/gen-image` на выдачу фиксированных URL по словарю.

