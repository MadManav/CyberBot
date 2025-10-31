import pickle
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Paths
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

ENSEMBLE_PATH = os.path.join(MODEL_DIR, 'ensemble.pkl')
VECTORIZER_PATH = os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl')

class PhishingEnsemble:
    def __init__(self):
        self.vectorizer = None
        self.xgb_model = None
        self.rf_model = None
        self.lr_model = None
        self.weights = [0.4, 0.35, 0.25]  # XGB, RF, LR
        
    def train(self, texts, labels):
        """
        Train ensemble on phishing dataset
        texts: List of messages/URLs
        labels: List of 0 (safe) or 1 (phishing)
        """
        print("🔧 Training Ensemble Model...")
        
        # Vectorize text
        self.vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.95
        )
        X = self.vectorizer.fit_transform(texts)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train XGBoost
        print("Training XGBoost...")
        self.xgb_model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            eval_metric='logloss'
        )
        self.xgb_model.fit(X_train, y_train)
        xgb_acc = accuracy_score(y_test, self.xgb_model.predict(X_test))
        print(f"  XGBoost Accuracy: {xgb_acc:.2%}")
        
        # Train Random Forest
        print("Training Random Forest...")
        self.rf_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=5,
            random_state=42
        )
        self.rf_model.fit(X_train, y_train)
        rf_acc = accuracy_score(y_test, self.rf_model.predict(X_test))
        print(f"  Random Forest Accuracy: {rf_acc:.2%}")
        
        # Train Logistic Regression
        print("Training Logistic Regression...")
        self.lr_model = LogisticRegression(
            max_iter=500,
            C=1.0,
            random_state=42
        )
        self.lr_model.fit(X_train, y_train)
        lr_acc = accuracy_score(y_test, self.lr_model.predict(X_test))
        print(f"  Logistic Regression Accuracy: {lr_acc:.2%}")
        
        # Test ensemble
        ensemble_preds = self.predict_batch(X_test)
        ensemble_acc = accuracy_score(y_test, (ensemble_preds > 0.5).astype(int))
        print(f"\n✅ Ensemble Accuracy: {ensemble_acc:.2%}")
        
        # Save models
        self.save()
        
    def predict(self, text):
        """
        Predict single message
        Returns: probability of phishing (0-1)
        """
        X = self.vectorizer.transform([text])
        return self.predict_batch(X)[0]
    
    def predict_batch(self, X):
        """
        Predict batch of vectorized samples
        Returns: array of probabilities
        """
        # Get predictions from each model
        xgb_proba = self.xgb_model.predict_proba(X)[:, 1]
        rf_proba = self.rf_model.predict_proba(X)[:, 1]
        lr_proba = self.lr_model.predict_proba(X)[:, 1]
        
        # Weighted ensemble
        ensemble_proba = (
            xgb_proba * self.weights[0] +
            rf_proba * self.weights[1] +
            lr_proba * self.weights[2]
        )
        
        return ensemble_proba
    
    def save(self):
        """Save all models"""
        ensemble_data = {
            'xgb': self.xgb_model,
            'rf': self.rf_model,
            'lr': self.lr_model,
            'weights': self.weights
        }
        with open(ENSEMBLE_PATH, 'wb') as f:
            pickle.dump(ensemble_data, f)
        with open(VECTORIZER_PATH, 'wb') as f:
            pickle.dump(self.vectorizer, f)
        print(f"✅ Models saved to {MODEL_DIR}")
    
    def load(self):
        """Load pre-trained models"""
        with open(ENSEMBLE_PATH, 'rb') as f:
            ensemble_data = pickle.load(f)
        self.xgb_model = ensemble_data['xgb']
        self.rf_model = ensemble_data['rf']
        self.lr_model = ensemble_data['lr']
        self.weights = ensemble_data['weights']
        
        with open(VECTORIZER_PATH, 'rb') as f:
            self.vectorizer = pickle.load(f)
        print("✅ Ensemble models loaded")


def load_dataset(filepath=None):
    """
    Load phishing dataset from Excel or CSV
    Expected format: 'text' column (message/URL) and 'label' column (0/1)
    """
    if filepath and os.path.exists(filepath):
        if filepath.endswith('.xlsx'):
            # Read Excel file
            df = pd.read_excel(filepath)
            # Assuming first column is text and second is label
            text_col = df.columns[0]
            label_col = df.columns[1] if len(df.columns) > 1 else None
            
            texts = df[text_col].astype(str).tolist()
            if label_col:
                labels = df[label_col].astype(int).tolist()
            else:
                # If no label column, assume all are phishing (1)
                labels = [1] * len(texts)
                
            return texts, labels
        else:
            # Fallback to CSV
            df = pd.read_csv(filepath)
            return df['text'].tolist(), df['label'].tolist()
    
    # Fallback: Built-in training data
    print("⚠️  No dataset file found, using built-in training data...")
    return get_builtin_dataset()


def get_builtin_dataset():
    """
    Built-in phishing dataset for quick start
    """
    phishing_samples = [
        "Urgent: Your account will be suspended. Click here to verify immediately",
        "Congratulations! You've won $1,000,000. Claim your prize now",
        "Action required: Confirm your password to avoid account closure",
        "Your package delivery failed. Update payment info: http://fake-delivery.com",
        "Security alert: Suspicious login detected. Verify here immediately",
        # Add 100+ more samples here...
    ] * 10  # Duplicate for demo
    
    legitimate_samples = [
        "Hi, thanks for your email. Let's schedule a meeting next week",
        "Your order #12345 has been shipped and will arrive tomorrow",
        "Welcome to our newsletter! Here's this month's update",
        "Meeting reminder: Project sync at 3 PM today",
        "Thank you for subscribing to our service",
        # Add 100+ more samples here...
    ] * 10
    
    texts = phishing_samples + legitimate_samples
    labels = [1] * len(phishing_samples) + [0] * len(legitimate_samples)
    
    return texts, labels


# Global instance
_ensemble = None

def get_ensemble():
    """Get or create ensemble instance"""
    global _ensemble
    if _ensemble is None:
        _ensemble = PhishingEnsemble()
        if os.path.exists(ENSEMBLE_PATH):
            _ensemble.load()
        else:
            print("⚠️  No trained model found. Training new ensemble...")
            texts, labels = load_dataset()
            _ensemble.train(texts, labels)
    return _ensemble


def predict_phishing(text):
    """
    Main prediction function
    Returns: probability of phishing (0-1)
    """
    ensemble = get_ensemble()
    return float(ensemble.predict(text))


# Training script
if __name__ == "__main__":
    print("🚀 Training Phishing Ensemble Model\n")
    
    # Try to load from Excel file first
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    excel_file = os.path.join(data_dir, 'malicious_phish.xlsx')
    
    if os.path.exists(excel_file):
        print(f"📊 Loading dataset from: {excel_file}")
        texts, labels = load_dataset(excel_file)
    else:
        print("⚠️  Excel file not found, using built-in data")
        texts, labels = get_builtin_dataset()
    
    print(f"Dataset size: {len(texts)} samples")
    print(f"Phishing: {sum(labels)}, Legitimate: {len(labels) - sum(labels)}\n")
    
    ensemble = PhishingEnsemble()
    ensemble.train(texts, labels)
    
    # Test prediction
    test_text = "Urgent! Click here to verify your account now"
    score = ensemble.predict(test_text)
    print(f"\n🧪 Test: '{test_text}'")
    print(f"Phishing Score: {score:.2%}")