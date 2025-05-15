import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report
import joblib
from scipy.stats import randint

# Конфигурация
FEATURES = [
    'dur', 'proto', 'service', 'state',
    'sbytes', 'dbytes', 'sttl', 'dttl',
    'sload', 'dload', 'swin', 'dwin',
    'ct_srv_src', 'ct_state_ttl'
]

TARGET = 'attack_cat'

def main():
    # 1. Загрузка данных
    df = pd.read_csv('UNSW_NB15_training-set.csv')

    # 2. Предобработка данных
    # Заполнение пропусков
    df[FEATURES] = df[FEATURES].fillna(0)

    # Кодирование категориальных признаков
    categorical_cols = ['proto', 'service', 'state']
    encoders = {}

    for col in categorical_cols:
        encoder = OrdinalEncoder(
            handle_unknown='use_encoded_value',
            unknown_value=-1
        )
        df[col] = encoder.fit_transform(df[[col]]).astype(int)
        encoders[col] = encoder

    # 3. Подготовка данных
    X = df[FEATURES]
    y = df[TARGET]

    # Нормализация числовых признаков
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 4. Разделение данных
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # 5. Создание модели RandomForest
    rf = RandomForestClassifier(random_state=42, n_jobs=-1)

    # 6. Подбор гиперпараметров с RandomizedSearchCV
    param_dist = {
        'n_estimators': randint(100, 500),
        'max_depth': [10, 15, 20, None],
        'min_samples_split': randint(2, 10),
        'min_samples_leaf': randint(1, 5),
        'class_weight': ['balanced', None]
    }

    random_search = RandomizedSearchCV(
        estimator=rf,
        param_distributions=param_dist,
        n_iter=30,  # Количество случайных параметров для проверки
        cv=3,       # 3-кратная кросс-валидация
        verbose=2,
        random_state=42,
        n_jobs=-1,
        scoring='f1_weighted'
    )

    # 7. Обучение модели с подбором гиперпараметров
    random_search.fit(X_train, y_train)

    # 8. Результаты
    print("Лучшие параметры:", random_search.best_params_)
    print("Лучший результат (f1_weighted):", random_search.best_score_)

    # 9. Оценка на тестовых данных
    y_pred = random_search.best_estimator_.predict(X_test)
    print(classification_report(y_test, y_pred))

    # 10. Сохранение модели и артефактов
    joblib.dump(random_search.best_estimator_, 'model/model.pkl')
    joblib.dump(scaler, 'model/scaler.pkl')
    joblib.dump(encoders, 'model/encoders.pkl')
    joblib.dump(FEATURES, 'model/features.pkl')  # Сохраняем порядок признаков

if __name__ == '__main__':
    main()
