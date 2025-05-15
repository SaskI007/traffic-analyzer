# Traffic Analyzer
Это дипломный проект для анализа сетевого трафика и обнаружения аномалий на основе искусственного интеллекта.
## Как запустить
1.	Установи зависимости:
pip install -r requirements.txt
2.	Запусти backend:
uvicorn app:app --host 0.0.0.0 --port 5000
3.	Запусти frontend:
npm install
npm run dev
## Модель
Файл `model.pkl` не включен в репозиторий из-за ограничений GitHub (размер > 100 МБ). Загрузите модель вручную и поместите её в `backend/model/model.pkl`.
https://drive.google.com/file/d/134hsoFdEf8hpN-8xd9MW1aHqNQnWP24x/view?usp=sharing
