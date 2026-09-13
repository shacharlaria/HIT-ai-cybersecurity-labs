import time
import json
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

class SOCModelEvaluator:
    def __init__(self, ground_truth_labels, predicted_labels):
        """
        ground_truth_labels: רשימה של תוויות האמת (0 = לגיטימי, 1 = תקיפה אמיתית)
        predicted_labels: רשימה של התוויות שזוהו על ידי המערכת (0 או 1)
        """
        self.y_true = np.array(ground_truth_labels)
        self.y_pred = np.array(predicted_labels)

    def compute_metrics(self):
        """חישוב מדדי איכות סטטיסטיים למחקר הפרויקט"""
        precision = precision_score(self.y_true, self.y_pred, zero_division=0)
        recall = recall_score(self.y_true, self.y_pred, zero_division=0)
        f1 = f1_score(self.y_true, self.y_pred, zero_division=0)
        
        # חישוב Confusion Matrix לקבלת False Positive Rate
        tn, fp, fn, tp = confusion_matrix(self.y_true, self.y_pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        metrics_report = {
            "Precision": round(float(precision), 4),
            "Recall": round(float(recall), 4),
            "F1-Score": round(float(f1), 4),
            "False Positive Rate (FPR)": round(float(fpr), 4),
            "True Positives (TP)": int(tp),
            "False Positives (FP)": int(fp),
            "True Negatives (TN)": int(tn),
            "False Negatives (FN)": int(fn)
        }
        return metrics_report

def benchmark_execution_speed(detector_func, dataset, iterations=10):
    """בדיקת ביצועים וזמני ריצה (Benchmarking) עבור מודל ה-Isolation Forest או סורק החתימות"""
    execution_times = []
    for _ in range(iterations):
        start_time = time.perf_counter()
        detector_func(dataset)
        end_time = time.perf_counter()
        execution_times.append(end_time - start_time)
    
    avg_time = np.mean(execution_times)
    return {
        "Average Execution Time (s)": round(float(avg_time), 6),
        "Iterations Tested": iterations
    }

# דוגמה להפעלה והפקת דוח מחקרי
if __name__ == "__main__":
    # דוגמה לסימולציה של תוצאות (Ground Truth מול זיהוי המערכת)
    sample_ground_truth = [1, 1, 0, 0, 1, 0, 0, 1, 0, 0] # 1 = תקיפה, 0 = תעבורת רשת לגיטימית
    sample_predictions  = [1, 0, 0, 1, 1, 0, 0, 1, 0, 0] # זיהוי של המערכת ההיברידית

    evaluator = SOCModelEvaluator(sample_ground_truth, sample_predictions)
    report = evaluator.compute_metrics()

    print("=== SOC HYBRID MODEL EVALUATION REPORT ===")
    print(json.dumps(report, indent=4, ensure_ascii=False))

    # דוגמה לבנצ'מרקינג מהירות
    dummy_dataset = list(range(10000))
    dummy_detector = lambda data: [x * 2 for x in data]
    perf_report = benchmark_execution_speed(dummy_detector, dummy_dataset)
    
    print("\n=== PERFORMANCE BENCHMARKING REPORT ===")
    print(json.dumps(perf_report, indent=4, ensure_ascii=False))