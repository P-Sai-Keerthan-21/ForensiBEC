"""Reproducible ML baselines for the research layer.

These models exist to ANSWER A RESEARCH QUESTION, not to replace the forensic
engine. The engine remains the system's decision path; these are the
comparison arm that makes "does evidence fusion beat text-only classification?"
an experimental claim rather than an assertion.

Design constraints
------------------
* Three classical, interpretable baselines only (Rule 8: no model zoo).
* Every random seed is fixed, so a rerun reproduces the numbers exactly.
* Pipelines are built with sklearn's `Pipeline`/`ColumnTransformer` so that
  vectorisers are fitted on training data only - fitting a vectoriser on the
  full corpus would leak test-set vocabulary into training.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC

from .features import ExtractedSample

RANDOM_SEED = 20260918


@dataclass
class ModelSpec:
    """A named baseline and its exact configuration."""

    key: str
    label: str
    factory: Any
    rationale: str

    def config(self) -> dict[str, Any]:
        model = self.factory()
        return {
            "key": self.key,
            "label": self.label,
            "class": type(model).__name__,
            "params": {k: _jsonable(v) for k, v in model.get_params().items()},
            "rationale": self.rationale,
        }


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


MODELS: tuple[ModelSpec, ...] = (
    ModelSpec(
        key="logistic_regression",
        label="Logistic Regression",
        factory=lambda: LogisticRegression(
            max_iter=2000, random_state=RANDOM_SEED, class_weight="balanced",
        ),
        rationale=(
            "Linear and directly inspectable: coefficients map to features, so a "
            "prediction can be decomposed the way the rule engine's score can. "
            "Also yields calibrated-ish probabilities for threshold analysis."
        ),
    ),
    ModelSpec(
        key="random_forest",
        label="Random Forest",
        factory=lambda: RandomForestClassifier(
            n_estimators=300, random_state=RANDOM_SEED, class_weight="balanced",
            n_jobs=-1, min_samples_leaf=2,
        ),
        rationale=(
            "Captures feature interactions the linear model cannot - the BEC "
            "pattern is conjunctive (identity AND financial AND pressure), which "
            "is exactly what tree ensembles represent well."
        ),
    ),
    ModelSpec(
        key="linear_svm",
        label="Linear SVM",
        factory=lambda: LinearSVC(
            random_state=RANDOM_SEED, class_weight="balanced", max_iter=5000, dual="auto",
        ),
        rationale=(
            "Standard strong baseline for high-dimensional sparse text; included "
            "to check that the TF-IDF arm is not being under-served by the "
            "logistic model."
        ),
    ),
)

MODELS_BY_KEY = {m.key: m for m in MODELS}


class FeatureSpace:
    """Builds the design matrix for a chosen set of feature groups.

    Fitted on training data only. `transform` on later splits reuses the
    fitted vocabulary and feature names, so an unseen token or feature in the
    test set is dropped rather than silently expanding the matrix.
    """

    def __init__(self, groups: list[str], use_text: bool) -> None:
        self.groups = [g for g in groups if g != "text"]
        self.use_text = use_text

        self.word_vec: TfidfVectorizer | None = None
        self.char_vec: TfidfVectorizer | None = None
        self.dict_vec: DictVectorizer | None = None
        self.scaler: MaxAbsScaler | None = None

    def _structured(self, samples: list[ExtractedSample]) -> list[dict[str, float]]:
        return [s.vector_for(self.groups) for s in samples]

    def fit_transform(self, samples: list[ExtractedSample]) -> csr_matrix:
        blocks: list[csr_matrix] = []

        if self.use_text:
            texts = [s.text for s in samples]
            self.word_vec = TfidfVectorizer(
                lowercase=True, ngram_range=(1, 2), max_features=5000,
                sublinear_tf=True, min_df=2,
            )
            self.char_vec = TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 5), max_features=5000,
                sublinear_tf=True, min_df=2,
            )
            blocks.append(self.word_vec.fit_transform(texts))
            blocks.append(self.char_vec.fit_transform(texts))

        if self.groups:
            rows = self._structured(samples)
            if rows and any(rows):
                self.dict_vec = DictVectorizer(sparse=True)
                matrix = self.dict_vec.fit_transform(rows)
                self.scaler = MaxAbsScaler()
                blocks.append(csr_matrix(self.scaler.fit_transform(matrix)))

        if not blocks:
            raise ValueError("feature space is empty - enable text or a feature group")
        return hstack(blocks, format="csr")

    def transform(self, samples: list[ExtractedSample]) -> csr_matrix:
        blocks: list[csr_matrix] = []

        if self.use_text and self.word_vec is not None and self.char_vec is not None:
            texts = [s.text for s in samples]
            blocks.append(self.word_vec.transform(texts))
            blocks.append(self.char_vec.transform(texts))

        if self.dict_vec is not None:
            matrix = self.dict_vec.transform(self._structured(samples))
            assert self.scaler is not None
            blocks.append(csr_matrix(self.scaler.transform(matrix)))

        if not blocks:
            raise ValueError("feature space is empty")
        return hstack(blocks, format="csr")

    @property
    def n_features(self) -> int:
        total = 0
        if self.word_vec is not None:
            total += len(self.word_vec.vocabulary_)
        if self.char_vec is not None:
            total += len(self.char_vec.vocabulary_)
        if self.dict_vec is not None:
            total += len(self.dict_vec.feature_names_)
        return total


def labels_of(samples: list[ExtractedSample]) -> np.ndarray:
    return np.array([s.label for s in samples], dtype=int)


def decision_scores(model: Any, matrix: csr_matrix) -> np.ndarray:
    """Continuous scores for ROC/PR, whatever the estimator exposes.

    LinearSVC has no `predict_proba`; its signed distance from the hyperplane
    is a valid ranking score for ROC-AUC, which is why it is used here rather
    than forcing a probability calibration the model was not fitted for.
    """
    if hasattr(model, "predict_proba"):
        return model.predict_proba(matrix)[:, 1]
    return model.decision_function(matrix)


def train(spec: ModelSpec, matrix: csr_matrix, y: np.ndarray) -> Any:
    model = spec.factory()
    dense_required = isinstance(model, RandomForestClassifier)
    model.fit(matrix.toarray() if dense_required else matrix, y)
    return model


def predict(model: Any, matrix: csr_matrix) -> tuple[np.ndarray, np.ndarray]:
    dense_required = isinstance(model, RandomForestClassifier)
    data = matrix.toarray() if dense_required else matrix
    return model.predict(data), decision_scores(model, data)
