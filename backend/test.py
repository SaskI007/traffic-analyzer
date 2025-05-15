import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
import joblib

# Загрузим тестовые данные
data = pd.read_csv("UNSW_NB15_testing-set.csv")

# Заменим дефисы ('-') на NaN
data.replace('-', np.nan, inplace=True)

# Обрабатываем категориальные столбцы перед заполниванием NaN
categorical_columns = ['proto', 'service', 'state', 'attack_cat']
for col in categorical_columns:
    label_encoder = LabelEncoder()
    data[col] = label_encoder.fit_transform(data[col].astype(str))

# Заполним NaN значения медианой для числовых столбцов
data.fillna(data.select_dtypes(include=[np.number]).median(), inplace=True)

# Заполним NaN значения наиболее частыми значениями для категориальных столбцов
for col in data.select_dtypes(include=['object']).columns:
    data[col].fillna(data[col].mode()[0], inplace=True)

# Разделим данные на признаки и метки
X = data.drop(columns=['id', 'label'])  # Убираем 'id' и 'label' из признаков
y = data['label']  # Метка для классификации

# Масштабируем данные
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Загрузим ранее обученную модель и скейлер
model = joblib.load("model/model.pkl")  # Предполагаем, что модель сохранена в файле random_forest_model.pkl
scaler = joblib.load("model/scaler.pkl")  # Сохраняйте и загружайте скейлер, если он был обучен

# Масштабируем тестовые данные с использованием того же скейлера
X_scaled = scaler.transform(X)

# Сделаем предсказания
y_pred = model.predict(X_scaled)

# Оценим качество модели
print(classification_report(y, y_pred))

# Пример предсказания для одного примера
example = X_scaled[0].reshape(1, -1)
pred = model.predict(example)
print(f"Предсказание для примера: {pred[0]}")
