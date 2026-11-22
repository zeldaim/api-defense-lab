"""비교용 이상 탐지 모델 — 모두 `decision_function(X)` (작을수록 이상) 를 내서 detector 에 그대로 끼울 수 있다.

detector 는 `model.joblib` 을 읽어 `decision_function` 만 부른다. 여기 클래스로 저장한 모델은
detector 가 이 모듈을 import 할 수 있어야 해서 detector/ 안에 둔다 (pipeline.py 와 같은 폴더 → sys.path).

  make_models()  →  {이름: 학습 전 모델}   (tools/ml_compare.py 가 같은 데이터로 학습 · 채점)
"""
from __future__ import annotations

import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.feature_selection import VarianceThreshold
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


class RobustZ:
    """통계 기준선 — 특징마다 중앙값 · MAD 로 정규화한 거리 중 가장 큰 값. 학습이 '평균과 퍼짐을 재는 것'뿐이다.
    점수 = -max_j |x_j - median_j| / (1.4826 · MAD_j). 퍼짐이 0 인 특징(학습 때 늘 같은 값)은 뺀다."""

    def fit(self, X, y=None):
        X = np.asarray(X, float)
        self.med_ = np.median(X, axis=0)
        mad = np.median(np.abs(X - self.med_), axis=0) * 1.4826
        iqr = (np.percentile(X, 75, axis=0) - np.percentile(X, 25, axis=0)) / 1.349
        self.scale_ = np.where(mad > 1e-9, mad, iqr)          # MAD 가 0 이면 IQR 로
        self.use_ = self.scale_ > 1e-9
        return self

    def decision_function(self, X):
        X = np.asarray(X, float)
        z = np.abs(X[:, self.use_] - self.med_[self.use_]) / self.scale_[self.use_]
        return -z.max(axis=1)


class AutoEncoder:
    """작은 오토인코더 — 표준화한 특징을 좁은 가운데 층(4)으로 눌렀다가 되살린다. 점수 = -복원 오차.
    정상만 배웠으니 정상과 다른 창은 잘 못 되살린다."""

    def __init__(self, hidden=(8, 4, 8), seed=42):
        self.hidden, self.seed = hidden, seed

    def fit(self, X, y=None):
        X = np.asarray(X, float)
        self.var_ = VarianceThreshold().fit(X)
        Xv = self.var_.transform(X)
        self.sc_ = StandardScaler().fit(Xv)
        Z = self.sc_.transform(Xv)
        self.net_ = MLPRegressor(hidden_layer_sizes=self.hidden, max_iter=3000, random_state=self.seed,
                                 early_stopping=False, alpha=1e-3).fit(Z, Z)
        return self

    def decision_function(self, X):
        Z = self.sc_.transform(self.var_.transform(np.asarray(X, float)))
        return -np.mean((self.net_.predict(Z) - Z) ** 2, axis=1)


def _scaled(model):
    """상수 특징 제거 → 표준화 → 모델 (거리 · 밀도 기반 모델은 특징 크기를 맞춰야 한다)"""
    return make_pipeline(VarianceThreshold(), StandardScaler(), model)


def make_models(seed: int = 42) -> dict:
    return {
        # 지금 쓰는 모델 — dvra_v1 과 같은 설정 (같은 데이터면 같은 모델이 나와야 한다)
        "IsolationForest": IsolationForest(n_estimators=300, contamination=0.01, random_state=seed),
        "RobustZ (통계)": RobustZ(),
        "LOF": _scaled(LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.01)),
        "OneClassSVM": _scaled(OneClassSVM(nu=0.01, gamma="scale")),
        "EllipticEnvelope": _scaled(EllipticEnvelope(contamination=0.01, support_fraction=0.9, random_state=seed)),
        "AutoEncoder": AutoEncoder(seed=seed),
    }
