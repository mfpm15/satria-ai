"""
SATRIA AI - Behavioral Anomaly Detection Agent
Advanced ML-based behavioral anomaly detection using multiple algorithms
"""

import asyncio
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import joblib

from satria.core.agent_base import BaseAgent
from satria.core.event_bus import event_bus
from satria.models.events import BaseEvent, EventCategory, EventClass
from satria.core.context_graph import context_graph


class AnomalyType(str, Enum):
    """Types of behavioral anomalies"""
    USER_BEHAVIOR = "user_behavior"
    NETWORK_TRAFFIC = "network_traffic"
    PROCESS_EXECUTION = "process_execution"
    FILE_ACCESS = "file_access"
    AUTHENTICATION = "authentication"
    SYSTEM_RESOURCE = "system_resource"


class ModelType(str, Enum):
    """ML model types for anomaly detection"""
    ISOLATION_FOREST = "isolation_forest"
    DBSCAN_CLUSTERING = "dbscan_clustering"
    STATISTICAL_OUTLIER = "statistical_outlier"
    LSTM_SEQUENCE = "lstm_sequence"
    AUTOENCODER = "autoencoder"


@dataclass
class AnomalyModel:
    """Anomaly detection model configuration"""
    model_id: str
    anomaly_type: AnomalyType
    model_type: ModelType
    model: Any = None
    scaler: StandardScaler = field(default_factory=StandardScaler)
    features: List[str] = field(default_factory=list)
    trained_at: Optional[datetime] = None
    accuracy_score: float = 0.0
    false_positive_rate: float = 0.0
    sample_count: int = 0
    retrain_threshold: int = 10000
    enabled: bool = True


@dataclass
class BehavioralProfile:
    """User/Entity behavioral profile"""
    entity_id: str
    entity_type: str  # user, host, service
    profile_data: Dict[str, Any] = field(default_factory=dict)
    baseline_features: Dict[str, float] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_count: int = 0
    anomaly_count: int = 0
    risk_score: float = 0.0


class BehavioralAnomalyDetector(BaseAgent):
    """
    Advanced Behavioral Anomaly Detection Agent
    Uses multiple ML algorithms for comprehensive behavioral analysis
    """

    def __init__(self):
        super().__init__(
            name="behavioral_anomaly_detector",
            description="Advanced ML-based behavioral anomaly detection",
            version="2.0.0"
        )

        self.models: Dict[str, AnomalyModel] = {}
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.anomalies_detected = 0
        self.events_processed = 0
        self.model_performance = {}

        # Feature extraction windows
        self.time_windows = {
            "short": timedelta(hours=1),
            "medium": timedelta(hours=6),
            "long": timedelta(hours=24)
        }

        # Training parameters
        self.min_training_samples = 1000
        self.retrain_interval = timedelta(hours=24)
        self.anomaly_threshold = 0.1  # 10% most anomalous

    async def initialize(self) -> bool:
        """Initialize anomaly detection models"""
        try:
            # Initialize ML models for different anomaly types
            await self._initialize_models()

            # Load existing behavioral profiles
            await self._load_behavioral_profiles()

            # Start model training and retraining tasks
            asyncio.create_task(self._periodic_model_training())
            asyncio.create_task(self._periodic_profile_update())

            logging.info("Behavioral Anomaly Detector initialized with ML models")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize Behavioral Anomaly Detector: {e}")
            return False

    async def _initialize_models(self):
        """Initialize all anomaly detection models"""

        # User Behavior Model - Isolation Forest
        self.models["user_behavior_if"] = AnomalyModel(
            model_id="user_behavior_if",
            anomaly_type=AnomalyType.USER_BEHAVIOR,
            model_type=ModelType.ISOLATION_FOREST,
            model=IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=200
            ),
            features=[
                "login_frequency", "login_hour_avg", "session_duration_avg",
                "failed_login_rate", "unique_hosts_accessed", "data_transferred",
                "privileged_actions", "off_hours_activity"
            ]
        )

        # Network Traffic Model - Statistical + Clustering
        self.models["network_dbscan"] = AnomalyModel(
            model_id="network_dbscan",
            anomaly_type=AnomalyType.NETWORK_TRAFFIC,
            model_type=ModelType.DBSCAN_CLUSTERING,
            model=DBSCAN(eps=0.5, min_samples=5),
            features=[
                "bytes_sent", "bytes_received", "connection_count",
                "unique_destinations", "port_diversity", "protocol_diversity",
                "external_connections", "suspicious_ports"
            ]
        )

        # Process Execution Model - Isolation Forest
        self.models["process_if"] = AnomalyModel(
            model_id="process_if",
            anomaly_type=AnomalyType.PROCESS_EXECUTION,
            model_type=ModelType.ISOLATION_FOREST,
            model=IsolationForest(contamination=0.05, random_state=42),
            features=[
                "process_frequency", "cpu_usage_avg", "memory_usage_avg",
                "child_process_count", "network_connections", "file_operations",
                "registry_operations", "privilege_escalations"
            ]
        )

        # File Access Model - Statistical Outlier Detection
        self.models["file_statistical"] = AnomalyModel(
            model_id="file_statistical",
            anomaly_type=AnomalyType.FILE_ACCESS,
            model_type=ModelType.STATISTICAL_OUTLIER,
            features=[
                "files_accessed", "directories_accessed", "file_size_avg",
                "sensitive_file_access", "creation_rate", "modification_rate",
                "deletion_rate", "permission_changes"
            ]
        )

        # Authentication Model - LSTM for sequence analysis
        self.models["auth_lstm"] = AnomalyModel(
            model_id="auth_lstm",
            anomaly_type=AnomalyType.AUTHENTICATION,
            model_type=ModelType.LSTM_SEQUENCE,
            features=[
                "auth_success_rate", "auth_timing_pattern", "source_ip_diversity",
                "user_agent_diversity", "geolocation_changes", "device_changes",
                "protocol_usage", "time_of_day_pattern"
            ]
        )

    async def process_event(self, event: BaseEvent) -> List[BaseEvent]:
        """Process events for behavioral anomaly detection"""
        try:
            self.events_processed += 1

            # Extract behavioral features from event
            features = await self._extract_behavioral_features(event)
            if not features:
                return [event]

            # Update behavioral profiles
            await self._update_behavioral_profile(event, features)

            # Run anomaly detection
            anomalies = await self._detect_anomalies(event, features)

            # Process detected anomalies
            if anomalies:
                await self._process_anomalies(event, anomalies)

            return [event]

        except Exception as e:
            logging.error(f"Error in behavioral anomaly detection: {e}")
            return [event]

    async def _extract_behavioral_features(self, event: BaseEvent) -> Dict[str, float]:
        """Extract behavioral features from event"""
        features = {}

        try:
            # Get entity information
            user_id = event.entity_ids.get("user")
            host_id = event.entity_ids.get("host")
            source_ip = event.entity_ids.get("source_ip")

            # Time-based features
            hour_of_day = event.timestamp.hour
            day_of_week = event.timestamp.weekday()
            is_weekend = day_of_week >= 5
            is_off_hours = hour_of_day < 7 or hour_of_day > 19

            # Get historical data for comparison
            historical_data = await self._get_historical_data(event)

            # User behavior features
            if user_id and event.event_category == EventCategory.IDENTITY_ACCESS_MANAGEMENT:
                user_profile = self.behavioral_profiles.get(f"user:{user_id}")

                features.update({
                    "login_frequency": self._calculate_login_frequency(user_id, historical_data),
                    "login_hour_avg": self._calculate_avg_login_hour(user_id, historical_data),
                    "session_duration_avg": self._calculate_avg_session_duration(user_id, historical_data),
                    "failed_login_rate": self._calculate_failed_login_rate(user_id, historical_data),
                    "unique_hosts_accessed": len(self._get_unique_hosts(user_id, historical_data)),
                    "privileged_actions": self._count_privileged_actions(user_id, historical_data),
                    "off_hours_activity": 1.0 if is_off_hours else 0.0,
                    "weekend_activity": 1.0 if is_weekend else 0.0
                })

            # Network traffic features
            if event.event_category == EventCategory.NETWORK_ACTIVITY:
                features.update({
                    "bytes_sent": float(event.enrichment.get("bytes_sent", 0)),
                    "bytes_received": float(event.enrichment.get("bytes_received", 0)),
                    "connection_count": self._count_network_connections(host_id, historical_data),
                    "unique_destinations": len(self._get_unique_destinations(host_id, historical_data)),
                    "external_connections": self._count_external_connections(host_id, historical_data),
                    "suspicious_ports": self._count_suspicious_ports(event, historical_data),
                    "protocol_diversity": self._calculate_protocol_diversity(host_id, historical_data)
                })

            # Process execution features
            if event.event_category == EventCategory.SYSTEM_ACTIVITY:
                features.update({
                    "process_frequency": self._calculate_process_frequency(event, historical_data),
                    "cpu_usage_avg": float(event.enrichment.get("cpu_usage", 0)),
                    "memory_usage_avg": float(event.enrichment.get("memory_usage", 0)),
                    "child_process_count": int(event.enrichment.get("child_processes", 0)),
                    "network_connections": int(event.enrichment.get("network_connections", 0)),
                    "file_operations": int(event.enrichment.get("file_operations", 0)),
                    "privilege_escalations": 1.0 if "privilege_escalation" in event.enrichment.get("tags", []) else 0.0
                })

            return features

        except Exception as e:
            logging.error(f"Error extracting behavioral features: {e}")
            return {}

    async def _detect_anomalies(self, event: BaseEvent, features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Detect anomalies using multiple ML models"""
        anomalies = []

        try:
            for model_id, model in self.models.items():
                if not model.enabled or not model.model:
                    continue

                # Check if event matches model type
                if not self._event_matches_model_type(event, model.anomaly_type):
                    continue

                # Prepare features for this model
                model_features = self._prepare_features_for_model(features, model)
                if not model_features or len(model_features) == 0:
                    continue

                # Run anomaly detection
                is_anomaly, anomaly_score = await self._run_model_detection(
                    model, model_features
                )

                if is_anomaly:
                    anomaly = {
                        "model_id": model_id,
                        "anomaly_type": model.anomaly_type.value,
                        "anomaly_score": anomaly_score,
                        "features_used": list(model_features.keys()),
                        "feature_values": model_features,
                        "detected_at": datetime.now(timezone.utc).isoformat()
                    }
                    anomalies.append(anomaly)

                    logging.info(f"Anomaly detected by {model_id}: score={anomaly_score:.3f}")

            return anomalies

        except Exception as e:
            logging.error(f"Error in anomaly detection: {e}")
            return []

    async def _run_model_detection(self, model: AnomalyModel, features: Dict[str, float]) -> Tuple[bool, float]:
        """Run specific ML model for anomaly detection"""
        try:
            # Convert features to array
            feature_array = np.array([list(features.values())]).reshape(1, -1)

            # Scale features if scaler is trained
            if hasattr(model.scaler, 'mean_'):
                feature_array = model.scaler.transform(feature_array)

            if model.model_type == ModelType.ISOLATION_FOREST:
                # Isolation Forest
                anomaly_score = model.model.decision_function(feature_array)[0]
                is_anomaly = model.model.predict(feature_array)[0] == -1
                # Convert to 0-1 score (lower is more anomalous)
                anomaly_score = max(0, min(1, (anomaly_score + 0.5) / 1.0))
                return is_anomaly, 1.0 - anomaly_score

            elif model.model_type == ModelType.DBSCAN_CLUSTERING:
                # DBSCAN treats outliers as anomalies
                cluster_label = model.model.fit_predict(feature_array)[0]
                is_anomaly = cluster_label == -1
                anomaly_score = 0.8 if is_anomaly else 0.1
                return is_anomaly, anomaly_score

            elif model.model_type == ModelType.STATISTICAL_OUTLIER:
                # Statistical outlier detection using z-score
                return self._statistical_outlier_detection(features, model)

            else:
                # Default statistical approach
                return self._statistical_outlier_detection(features, model)

        except Exception as e:
            logging.error(f"Error running model detection: {e}")
            return False, 0.0

    def _statistical_outlier_detection(self, features: Dict[str, float], model: AnomalyModel) -> Tuple[bool, float]:
        """Statistical outlier detection using z-scores"""
        try:
            # Get baseline statistics for this entity
            entity_id = f"{model.anomaly_type.value}_baseline"
            baseline = self.behavioral_profiles.get(entity_id)

            if not baseline or not baseline.baseline_features:
                return False, 0.0

            z_scores = []
            for feature_name, feature_value in features.items():
                if feature_name in baseline.baseline_features:
                    baseline_mean = baseline.baseline_features[feature_name]
                    baseline_std = baseline.profile_data.get(f"{feature_name}_std", 1.0)

                    if baseline_std > 0:
                        z_score = abs((feature_value - baseline_mean) / baseline_std)
                        z_scores.append(z_score)

            if not z_scores:
                return False, 0.0

            max_z_score = max(z_scores)
            avg_z_score = np.mean(z_scores)

            # Consider anomaly if average z-score > 2.5 or max z-score > 3
            is_anomaly = avg_z_score > 2.5 or max_z_score > 3.0
            anomaly_score = min(1.0, avg_z_score / 5.0)  # Normalize to 0-1

            return is_anomaly, anomaly_score

        except Exception as e:
            logging.error(f"Error in statistical outlier detection: {e}")
            return False, 0.0

    async def _process_anomalies(self, event: BaseEvent, anomalies: List[Dict[str, Any]]):
        """Process detected anomalies"""
        try:
            self.anomalies_detected += len(anomalies)

            # Calculate overall anomaly score
            overall_score = max(anomaly["anomaly_score"] for anomaly in anomalies)

            # Create anomaly detection event
            anomaly_event = BaseEvent(
                event_type="behavioral_anomaly",
                event_category=EventCategory.FINDINGS,
                event_class=EventClass.DETECTION_FINDING,
                timestamp=datetime.now(timezone.utc),
                entity_ids=event.entity_ids.copy(),
                message=f"Behavioral anomaly detected: {len(anomalies)} models triggered",
                risk=int(overall_score * 100),
                confidence=min(0.95, overall_score),
                enrichment={
                    "original_event_id": event.event_id,
                    "anomaly_details": anomalies,
                    "detection_models": [a["model_id"] for a in anomalies],
                    "max_anomaly_score": overall_score,
                    "anomaly_types": list(set(a["anomaly_type"] for a in anomalies))
                }
            )

            # Publish anomaly event
            await event_bus.publish(anomaly_event)

            # Update original event with anomaly information
            if "anomaly_detection" not in event.enrichment:
                event.enrichment["anomaly_detection"] = {}

            event.enrichment["anomaly_detection"].update({
                "is_anomaly": True,
                "anomaly_score": overall_score,
                "models_triggered": len(anomalies),
                "detection_details": anomalies
            })

            logging.info(f"Processed {len(anomalies)} behavioral anomalies with score {overall_score:.3f}")

        except Exception as e:
            logging.error(f"Error processing anomalies: {e}")

    async def _update_behavioral_profile(self, event: BaseEvent, features: Dict[str, float]):
        """Update behavioral profiles with new event data"""
        try:
            # Update profiles for different entity types
            entities_to_update = []

            if "user" in event.entity_ids:
                entities_to_update.append(f"user:{event.entity_ids['user']}")
            if "host" in event.entity_ids:
                entities_to_update.append(f"host:{event.entity_ids['host']}")
            if "source_ip" in event.entity_ids:
                entities_to_update.append(f"ip:{event.entity_ids['source_ip']}")

            for entity_key in entities_to_update:
                profile = self.behavioral_profiles.get(entity_key)

                if not profile:
                    # Create new profile
                    entity_type, entity_id = entity_key.split(":", 1)
                    profile = BehavioralProfile(
                        entity_id=entity_id,
                        entity_type=entity_type
                    )
                    self.behavioral_profiles[entity_key] = profile

                # Update profile with new features
                profile.event_count += 1
                profile.updated_at = datetime.now(timezone.utc)

                # Update rolling averages for baseline features
                alpha = 0.1  # Learning rate for exponential moving average
                for feature_name, feature_value in features.items():
                    if feature_name in profile.baseline_features:
                        # Update existing baseline
                        profile.baseline_features[feature_name] = (
                            (1 - alpha) * profile.baseline_features[feature_name] +
                            alpha * feature_value
                        )
                    else:
                        # Initialize new feature
                        profile.baseline_features[feature_name] = feature_value

                # Store additional profile data
                profile.profile_data.update({
                    "last_event_type": event.event_type,
                    "last_event_time": event.timestamp.isoformat(),
                    "recent_risk_scores": profile.profile_data.get("recent_risk_scores", [])[-10:] + [event.risk]
                })

        except Exception as e:
            logging.error(f"Error updating behavioral profile: {e}")

    async def _periodic_model_training(self):
        """Periodically retrain ML models with new data"""
        while self.is_running:
            try:
                await asyncio.sleep(3600)  # Check every hour

                for model in self.models.values():
                    if not model.enabled:
                        continue

                    # Check if model needs retraining
                    if (model.sample_count >= model.retrain_threshold and
                        (not model.trained_at or
                         datetime.now(timezone.utc) - model.trained_at > self.retrain_interval)):

                        await self._retrain_model(model)

            except Exception as e:
                logging.error(f"Error in periodic model training: {e}")
                await asyncio.sleep(3600)

    async def _retrain_model(self, model: AnomalyModel):
        """Retrain a specific ML model"""
        try:
            logging.info(f"Retraining model {model.model_id}")

            # Collect training data
            training_data = await self._collect_training_data(model)

            if len(training_data) < self.min_training_samples:
                logging.warning(f"Insufficient training data for {model.model_id}: {len(training_data)} samples")
                return

            # Prepare training data
            X = np.array([list(sample.values()) for sample in training_data])

            # Fit scaler
            model.scaler.fit(X)
            X_scaled = model.scaler.transform(X)

            # Train model
            if model.model_type == ModelType.ISOLATION_FOREST:
                model.model.fit(X_scaled)
            elif model.model_type == ModelType.DBSCAN_CLUSTERING:
                model.model.fit(X_scaled)

            # Update model metadata
            model.trained_at = datetime.now(timezone.utc)
            model.sample_count = len(training_data)

            # Evaluate model performance
            await self._evaluate_model_performance(model, X_scaled)

            logging.info(f"Successfully retrained model {model.model_id} with {len(training_data)} samples")

        except Exception as e:
            logging.error(f"Error retraining model {model.model_id}: {e}")

    # Helper methods for feature extraction
    def _calculate_login_frequency(self, user_id: str, historical_data: List[Dict]) -> float:
        """Calculate user login frequency"""
        login_events = [e for e in historical_data if e.get("event_type") == "authentication_success"]
        return len(login_events) / max(1, len(historical_data))

    def _calculate_avg_login_hour(self, user_id: str, historical_data: List[Dict]) -> float:
        """Calculate average login hour"""
        login_hours = [datetime.fromisoformat(e["timestamp"]).hour
                      for e in historical_data if e.get("event_type") == "authentication_success"]
        return np.mean(login_hours) if login_hours else 12.0

    def _calculate_failed_login_rate(self, user_id: str, historical_data: List[Dict]) -> float:
        """Calculate failed login rate"""
        total_auth = len([e for e in historical_data if "authentication" in e.get("event_type", "")])
        failed_auth = len([e for e in historical_data if e.get("event_type") == "authentication_failure"])
        return failed_auth / max(1, total_auth)

    def _event_matches_model_type(self, event: BaseEvent, anomaly_type: AnomalyType) -> bool:
        """Check if event matches model type"""
        type_mapping = {
            AnomalyType.USER_BEHAVIOR: [EventCategory.IDENTITY_ACCESS_MANAGEMENT],
            AnomalyType.NETWORK_TRAFFIC: [EventCategory.NETWORK_ACTIVITY],
            AnomalyType.PROCESS_EXECUTION: [EventCategory.SYSTEM_ACTIVITY],
            AnomalyType.FILE_ACCESS: [EventCategory.SYSTEM_ACTIVITY],
            AnomalyType.AUTHENTICATION: [EventCategory.IDENTITY_ACCESS_MANAGEMENT]
        }
        return event.event_category in type_mapping.get(anomaly_type, [])

    def _prepare_features_for_model(self, features: Dict[str, float], model: AnomalyModel) -> Dict[str, float]:
        """Prepare features specific to model"""
        return {k: v for k, v in features.items() if k in model.features}

    async def _get_historical_data(self, event: BaseEvent) -> List[Dict]:
        """Get historical data for entity (mock implementation)"""
        # In production, this would query the context graph or time series database
        return []

    async def _save_model(self, model_id: str) -> None:
        """Save model to disk"""
        try:
            model = self.models[model_id]
            if model.model_object:
                # In production, save model to persistent storage
                self.logger.debug(f"Model {model_id} saved (mock)")
        except Exception as e:
            self.logger.error(f"Error saving model {model_id}: {e}")

    async def _save_behavioral_profiles(self) -> None:
        """Save behavioral profiles to disk"""
        try:
            # In production, save profiles to persistent storage
            self.logger.debug(f"Saved {len(self.behavioral_profiles)} behavioral profiles (mock)")
        except Exception as e:
            self.logger.error(f"Error saving behavioral profiles: {e}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutdown"""
        try:
            # Save models to disk before shutdown
            for model_id, model in self.models.items():
                if model.trained_at:
                    await self._save_model(model_id)

            # Save behavioral profiles
            await self._save_behavioral_profiles()

            self.logger.info("Behavioral anomaly detector cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get anomaly detector metrics"""
        model_stats = {}
        for model_id, model in self.models.items():
            model_stats[model_id] = {
                "enabled": model.enabled,
                "trained": model.trained_at is not None,
                "sample_count": model.sample_count,
                "accuracy_score": model.accuracy_score,
                "false_positive_rate": model.false_positive_rate
            }

        return {
            **super().get_metrics(),
            "events_processed": self.events_processed,
            "anomalies_detected": self.anomalies_detected,
            "behavioral_profiles": len(self.behavioral_profiles),
            "active_models": len([m for m in self.models.values() if m.enabled]),
            "model_statistics": model_stats
        }


# Global instance
behavioral_anomaly_detector = BehavioralAnomalyDetector()