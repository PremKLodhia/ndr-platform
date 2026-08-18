"""
Visualization and metrics reporting tools for NDR evaluation.
"""
import numpy as np
import pandas as pd
from typing import Dict, Any, List


class MetricsReporter:
    """Generates transparent benchmark evaluation reports."""

    @staticmethod
    def calculate_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
        """
        Calculate true positive, false positive, precision, recall, F1, and FPR.
        """
        from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="binary", zero_division=0
        )
        fpr = fp / max(fp + tn, 1)

        return {
            "True_Negatives": int(tn),
            "False_Positives": int(fp),
            "False_Negatives": int(fn),
            "True_Positives": int(tp),
            "Precision": round(float(precision), 4),
            "Recall": round(float(recall), 4),
            "F1_Score": round(float(f1), 4),
            "False_Positive_Rate": round(float(fpr), 4)
        }
