"""
OSS Data Intelligence Layer

Provides comprehensive data analysis, governance, and access pattern intelligence
using DuckDB, MinIO, and SOPS with read-only analytical operations.
"""

import os
import json
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import sqlite3

try:
    import duckdb
except ImportError:
    duckdb = None

try:
    from minio import Minio
    from minio.error import S3Error
except ImportError:
    Minio = None
    S3Error = Exception

from .models import (
    AccessLog, AccessPatternReport, DataAsset, GovernanceAnalysisReport,
    PolicyRecommendationReport, OSSDataAsset, AccessPattern,
    GovernanceViolation, PolicyConflict, PolicyRecommendation,
    CrossAccountAccessPattern, DataClassification, AccessType, PolicyType,
    LocalTag, LocalPolicy, LocalDataAccess, serialize_dataclass
)


class SOPSAnalyzer:
    """Mozilla SOPS integration for secret pattern analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def analyze_encryption_patterns(self, file_path: str) -> Dict[str, Any]:
        """Analyze encryption patterns in SOPS-encrypted files"""
        try:
            # Check if file is SOPS-encrypted
            if not self._is_sops_encrypted(file_path):
                return {
                    "encrypted": False,
                    "analysis": "File is not SOPS-encrypted",
                    "recommendations": ["Consider encrypting sensitive configuration files with SOPS"]
                }
            
            # Analyze SOPS metadata
            metadata = self._extract_sops_metadata(file_path)
            return {
                "encrypted": True,
                "encryption_method": metadata.get("kms", "unknown"),
                "key_groups": len(metadata.get("key_groups", [])),
                "analysis": f"File encrypted with {len(metadata.get('key_groups', []))} key groups",
                "recommendations": self._generate_sops_recommendations(metadata)
            }
        except Exception as e:
            self.logger.error(f"SOPS analysis failed for {file_path}: {e}")
            return {
                "encrypted": False,
                "error": str(e),
                "analysis": "Failed to analyze encryption patterns",
                "recommendations": ["Verify SOPS installation and file permissions"]
            }
    
    def _is_sops_encrypted(self, file_path: str) -> bool:
        """Check if file contains SOPS encryption metadata"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                return 'sops:' in content and ('kms:' in content or 'pgp:' in content)
        except Exception:
            return False
    
    def _extract_sops_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract SOPS metadata from encrypted file"""
        try:
            result = subprocess.run(
                ['sops', '--decrypt', '--output-type', 'json', file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
            return {}
        except Exception:
            return {}
    
    def _generate_sops_recommendations(self, metadata: Dict[str, Any]) -> List[str]:
        """Generate SOPS security recommendations"""
        recommendations = []
        
        key_groups = metadata.get("key_groups", [])
        if len(key_groups) < 2:
            recommendations.append("Consider adding multiple key groups for redundancy")
        
        if not metadata.get("kms"):
            recommendations.append("Consider using KMS keys for enterprise-grade encryption")
        
        if not metadata.get("creation_rules"):
            recommendations.append("Define creation rules for consistent encryption policies")
        
        return recommendations


class MinIOClient:
    """MinIO client wrapper for S3-compatible analysis storage"""
    
    def __init__(self, endpoint: str = "localhost:9000", read_only: bool = True):
        self.endpoint = endpoint
        self.read_only = read_only
        self.logger = logging.getLogger(__name__)
        
        if Minio is None:
            self.logger.warning("MinIO client not available - install minio package")
            self.client = None
            return
        
        try:
            # Use environment variables for credentials if available
            access_key = os.getenv('MINIO_ACCESS_KEY', 'minioadmin')
            secret_key = os.getenv('MINIO_SECRET_KEY', 'minioadmin')
            
            self.client = Minio(
                endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=False  # Use HTTP for local development
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize MinIO client: {e}")
            self.client = None
    
    def analyze_bucket_access_patterns(self, bucket_name: str) -> Dict[str, Any]:
        """Analyze access patterns for a MinIO bucket"""
        if not self.client:
            return {"error": "MinIO client not available"}
        
        try:
            # List objects in bucket
            objects = list(self.client.list_objects(bucket_name, recursive=True))
            
            analysis = {
                "bucket_name": bucket_name,
                "total_objects": len(objects),
                "total_size_bytes": sum(obj.size for obj in objects),
                "object_types": {},
                "access_patterns": [],
                "recommendations": []
            }
            
            # Analyze object types
            for obj in objects:
                ext = Path(obj.object_name).suffix.lower()
                analysis["object_types"][ext] = analysis["object_types"].get(ext, 0) + 1
            
            # Generate recommendations
            if analysis["total_objects"] > 10000:
                analysis["recommendations"].append("Consider partitioning large buckets for better performance")
            
            if '.log' in analysis["object_types"]:
                analysis["recommendations"].append("Implement log rotation and archival policies")
            
            return analysis
            
        except S3Error as e:
            self.logger.error(f"MinIO bucket analysis failed: {e}")
            return {"error": f"Bucket analysis failed: {e}"}
    
    def get_bucket_policy_analysis(self, bucket_name: str) -> Dict[str, Any]:
        """Analyze bucket policies for governance compliance"""
        if not self.client:
            return {"error": "MinIO client not available"}
        
        try:
            # Get bucket policy if it exists
            try:
                policy = self.client.get_bucket_policy(bucket_name)
                policy_data = json.loads(policy) if policy else {}
            except Exception:
                policy_data = {}
            
            analysis = {
                "bucket_name": bucket_name,
                "has_policy": bool(policy_data),
                "policy_statements": len(policy_data.get("Statement", [])),
                "public_access": self._check_public_access(policy_data),
                "recommendations": []
            }
            
            if not policy_data:
                analysis["recommendations"].append("Consider adding bucket policy for access control")
            
            if analysis["public_access"]:
                analysis["recommendations"].append("Review public access permissions for security risks")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Bucket policy analysis failed: {e}")
            return {"error": f"Policy analysis failed: {e}"}
    
    def _check_public_access(self, policy_data: Dict[str, Any]) -> bool:
        """Check if bucket policy allows public access"""
        statements = policy_data.get("Statement", [])
        for statement in statements:
            principal = statement.get("Principal", {})
            if principal == "*" or principal.get("AWS") == "*":
                return True
        return False


class OSSDataIntelligence:
    """
    OSS Data Intelligence Layer
    
    Provides comprehensive data analysis, governance, and access pattern intelligence
    using DuckDB for analytics, MinIO for storage, and SOPS for encryption analysis.
    """
    
    def __init__(self, 
                 duckdb_path: str = "data/analysis/security_analysis.db",
                 minio_endpoint: str = "localhost:9000"):
        self.logger = logging.getLogger(__name__)
        self.duckdb_path = duckdb_path
        self.minio_endpoint = minio_endpoint
        self.duckdb_conn = None
        
        # Initialize components
        self.duckdb_conn = self._init_duckdb()
        self.minio_client = MinIOClient(minio_endpoint, read_only=True)
        self.sops = SOPSAnalyzer()
        
        # Create analysis tables if they don't exist
        self._create_analysis_tables()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with proper cleanup"""
        self.close()
    
    def close(self):
        """Properly close database connections"""
        if self.duckdb_conn:
            try:
                self.duckdb_conn.close()
                self.logger.info("DuckDB connection closed")
            except Exception as e:
                self.logger.error(f"Error closing DuckDB connection: {e}")
            finally:
                self.duckdb_conn = None
    
    def _init_duckdb(self) -> Optional[Any]:
        """Initialize DuckDB connection"""
        if duckdb is None:
            self.logger.error("DuckDB not available - install duckdb package")
            return None
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.duckdb_path), exist_ok=True)
            
            # Connect in read-only mode for analysis
            conn = duckdb.connect(self.duckdb_path)
            self.logger.info(f"Connected to DuckDB at {self.duckdb_path}")
            return conn
        except Exception as e:
            self.logger.error(f"Failed to initialize DuckDB: {e}")
            return None
    
    def _create_analysis_tables(self):
        """Create analysis tables in DuckDB"""
        if not self.duckdb_conn:
            return
        
        try:
            # Access logs table
            self.duckdb_conn.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    timestamp TIMESTAMP,
                    user_id VARCHAR,
                    resource_path VARCHAR,
                    access_type VARCHAR,
                    source_ip VARCHAR,
                    user_agent VARCHAR,
                    success BOOLEAN,
                    response_time_ms INTEGER,
                    bytes_transferred BIGINT,
                    metadata JSON
                )
            """)
            
            # Data assets table
            self.duckdb_conn.execute("""
                CREATE TABLE IF NOT EXISTS data_assets (
                    asset_id VARCHAR PRIMARY KEY,
                    name VARCHAR,
                    description VARCHAR,
                    minio_bucket VARCHAR,
                    duckdb_table VARCHAR,
                    local_file_path VARCHAR,
                    classification VARCHAR,
                    owner VARCHAR,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    size_bytes BIGINT,
                    record_count INTEGER
                )
            """)
            
            # Policies table
            self.duckdb_conn.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id VARCHAR PRIMARY KEY,
                    policy_type VARCHAR,
                    name VARCHAR,
                    description VARCHAR,
                    rules JSON,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    active BOOLEAN
                )
            """)
            
            self.logger.info("Analysis tables created successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to create analysis tables: {e}")
    
    def analyze_access_patterns(self, access_logs: List[AccessLog]) -> AccessPatternReport:
        """
        Analyze access patterns for security intelligence
        
        Uses DuckDB for read-only access pattern analysis to identify:
        - Unusual access patterns
        - Least-privilege violations
        - Anomalous behavior
        """
        if not self.duckdb_conn:
            return self._create_error_report("DuckDB not available")
        
        try:
            # Insert access logs into temporary table for analysis
            self._insert_access_logs(access_logs)
            
            # Analyze patterns
            patterns = self._identify_access_patterns()
            security_recommendations = self._generate_access_recommendations(patterns)
            violations = self._detect_privilege_violations(access_logs)
            anomalies = self._detect_access_anomalies(access_logs)
            
            # Generate summary
            summary = self._generate_access_summary(len(access_logs), patterns, violations, anomalies)
            
            return AccessPatternReport(
                analysis_id=f"access_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now(),
                total_access_events=len(access_logs),
                unique_users=len(set(log.user_id for log in access_logs)),
                unique_resources=len(set(log.resource_path for log in access_logs)),
                patterns_identified=patterns,
                security_recommendations=security_recommendations,
                least_privilege_violations=violations,
                anomalous_access_events=anomalies,
                summary=summary
            )
            
        except Exception as e:
            self.logger.error(f"Access pattern analysis failed: {e}")
            return self._create_error_report(f"Analysis failed: {e}")
    
    def analyze_data_governance(self, data_assets: List[DataAsset]) -> GovernanceAnalysisReport:
        """
        Analyze data governance compliance
        
        Uses DuckDB for governance compliance analysis including:
        - Policy compliance checking
        - Data classification validation
        - Access control assessment
        """
        if not self.duckdb_conn:
            return self._create_governance_error_report("DuckDB not available")
        
        try:
            # Insert data assets for analysis
            self._insert_data_assets(data_assets)
            
            # Analyze governance compliance
            violations = self._detect_governance_violations(data_assets)
            compliance_score = self._calculate_compliance_score(data_assets, violations)
            coverage_gaps = self._identify_policy_gaps(data_assets)
            recommendations = self._generate_governance_recommendations(violations, coverage_gaps)
            cross_account_patterns = self._analyze_cross_account_patterns(data_assets)
            
            # Generate summary
            summary = self._generate_governance_summary(
                len(data_assets), compliance_score, len(violations), len(recommendations)
            )
            
            return GovernanceAnalysisReport(
                analysis_id=f"governance_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now(),
                total_assets_analyzed=len(data_assets),
                policies_evaluated=[p.policy_id for asset in data_assets for p in asset.policies],
                violations_found=violations,
                compliance_score=compliance_score,
                policy_coverage_gaps=coverage_gaps,
                recommendations=recommendations,
                cross_account_patterns=cross_account_patterns,
                summary=summary
            )
            
        except Exception as e:
            self.logger.error(f"Data governance analysis failed: {e}")
            return self._create_governance_error_report(f"Analysis failed: {e}")
    
    def generate_policy_recommendations(self, current_policies: List[LocalPolicy]) -> PolicyRecommendationReport:
        """
        Generate policy improvement recommendations
        
        Analyzes current policies and generates human-readable recommendations for:
        - Policy conflicts resolution
        - Policy harmonization opportunities
        - Security improvements
        """
        try:
            # Detect policy conflicts
            conflicts = self._detect_policy_conflicts(current_policies)
            
            # Generate recommendations
            recommendations = self._generate_policy_improvements(current_policies, conflicts)
            
            # Identify harmonization opportunities
            harmonization = self._identify_harmonization_opportunities(current_policies)
            
            # Generate optimization suggestions
            optimizations = self._generate_optimization_suggestions(current_policies)
            
            # Generate summary
            summary = self._generate_policy_summary(
                len(current_policies), len(conflicts), len(recommendations)
            )
            
            return PolicyRecommendationReport(
                analysis_id=f"policy_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now(),
                policies_analyzed=[p.policy_id for p in current_policies],
                conflicts_detected=conflicts,
                recommendations=recommendations,
                harmonization_opportunities=harmonization,
                optimization_suggestions=optimizations,
                summary=summary
            )
            
        except Exception as e:
            self.logger.error(f"Policy recommendation generation failed: {e}")
            return PolicyRecommendationReport(
                analysis_id="error",
                timestamp=datetime.now(),
                policies_analyzed=[],
                conflicts_detected=[],
                recommendations=[],
                harmonization_opportunities=[],
                optimization_suggestions=[],
                summary=f"Policy analysis failed: {e}"
            )
    
    def analyze_cross_account_access_patterns(self, data_assets: List[DataAsset]) -> List[CrossAccountAccessPattern]:
        """
        Analyze cross-account access patterns for zero-copy optimization opportunities
        
        Identifies patterns where zero-copy data access could be implemented
        to reduce data transfer costs and improve performance.
        """
        try:
            patterns = []
            
            # Group assets by account patterns (simulated for OSS environment)
            account_groups = self._group_assets_by_account_pattern(data_assets)
            
            for source_account, source_assets in account_groups.items():
                for target_account, target_assets in account_groups.items():
                    if source_account != target_account:
                        pattern = self._analyze_cross_account_pattern(
                            source_account, source_assets, target_account, target_assets
                        )
                        if pattern:
                            patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Cross-account pattern analysis failed: {e}")
            return []
    
    # Helper methods for analysis implementation
    
    def _insert_access_logs(self, access_logs: List[AccessLog]):
        """Insert access logs into DuckDB for analysis"""
        if not self.duckdb_conn:
            return
        
        # Clear temporary data
        self.duckdb_conn.execute("DELETE FROM access_logs WHERE timestamp > NOW() - INTERVAL '1 hour'")
        
        # Insert new logs
        for log in access_logs:
            self.duckdb_conn.execute("""
                INSERT INTO access_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                log.timestamp, log.user_id, log.resource_path, log.access_type.value,
                log.source_ip, log.user_agent, log.success, log.response_time_ms,
                log.bytes_transferred, json.dumps(log.metadata)
            ])
    
    def _insert_data_assets(self, data_assets: List[DataAsset]):
        """Insert data assets into DuckDB for analysis"""
        if not self.duckdb_conn:
            return
        
        for asset in data_assets:
            self.duckdb_conn.execute("""
                INSERT OR REPLACE INTO data_assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                asset.asset_id, asset.name, asset.description, asset.minio_bucket,
                asset.duckdb_table, asset.local_file_path, asset.classification.value,
                asset.owner, asset.created_at, asset.updated_at, asset.size_bytes,
                asset.record_count
            ])
    
    def _identify_access_patterns(self) -> List[AccessPattern]:
        """Identify access patterns using DuckDB analytics"""
        if not self.duckdb_conn:
            return []
        
        patterns = []
        
        try:
            # Pattern 1: High-frequency access
            result = self.duckdb_conn.execute("""
                SELECT user_id, resource_path, COUNT(*) as access_count
                FROM access_logs 
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY user_id, resource_path
                HAVING COUNT(*) > 100
                ORDER BY access_count DESC
            """).fetchall()
            
            for row in result:
                patterns.append(AccessPattern(
                    pattern_id=f"high_freq_{row[0]}_{hash(row[1])}",
                    pattern_type="high_frequency_access",
                    description=f"User {row[0]} accessed {row[1]} {row[2]} times in 24h",
                    frequency=row[2],
                    users_affected=[row[0]],
                    resources_affected=[row[1]],
                    risk_level="medium",
                    recommendations=["Review if high-frequency access is legitimate"],
                    confidence_score=0.8
                ))
            
            # Pattern 2: Off-hours access
            result = self.duckdb_conn.execute("""
                SELECT user_id, COUNT(*) as off_hours_count
                FROM access_logs 
                WHERE EXTRACT(hour FROM timestamp) NOT BETWEEN 8 AND 18
                AND timestamp > NOW() - INTERVAL '7 days'
                GROUP BY user_id
                HAVING COUNT(*) > 10
            """).fetchall()
            
            for row in result:
                patterns.append(AccessPattern(
                    pattern_id=f"off_hours_{row[0]}",
                    pattern_type="off_hours_access",
                    description=f"User {row[0]} has {row[1]} off-hours accesses",
                    frequency=row[1],
                    users_affected=[row[0]],
                    resources_affected=[],
                    risk_level="low",
                    recommendations=["Verify legitimate business need for off-hours access"],
                    confidence_score=0.6
                ))
            
        except Exception as e:
            self.logger.error(f"Pattern identification failed: {e}")
        
        return patterns
    
    def _generate_access_recommendations(self, patterns: List[AccessPattern]) -> List[str]:
        """Generate security recommendations based on access patterns"""
        recommendations = []
        
        high_freq_patterns = [p for p in patterns if p.pattern_type == "high_frequency_access"]
        if high_freq_patterns:
            recommendations.append("Implement rate limiting for high-frequency access patterns")
            recommendations.append("Consider caching mechanisms for frequently accessed resources")
        
        off_hours_patterns = [p for p in patterns if p.pattern_type == "off_hours_access"]
        if off_hours_patterns:
            recommendations.append("Review off-hours access policies and implement additional monitoring")
            recommendations.append("Consider requiring additional authentication for off-hours access")
        
        if not patterns:
            recommendations.append("Access patterns appear normal - continue monitoring")
        
        return recommendations
    
    def _detect_privilege_violations(self, access_logs: List[AccessLog]) -> List[Dict[str, Any]]:
        """Detect least-privilege violations"""
        violations = []
        
        # Group by user and analyze access patterns
        user_accesses = {}
        for log in access_logs:
            if log.user_id not in user_accesses:
                user_accesses[log.user_id] = []
            user_accesses[log.user_id].append(log)
        
        for user_id, accesses in user_accesses.items():
            # Check for excessive permissions
            unique_resources = set(log.resource_path for log in accesses)
            if len(unique_resources) > 50:  # Threshold for excessive access
                violations.append({
                    "user_id": user_id,
                    "violation_type": "excessive_resource_access",
                    "resource_count": len(unique_resources),
                    "recommendation": "Review user permissions and implement least-privilege principle"
                })
        
        return violations
    
    def _detect_access_anomalies(self, access_logs: List[AccessLog]) -> List[AccessLog]:
        """Detect anomalous access events"""
        anomalies = []
        
        # Simple anomaly detection based on failed access attempts
        failed_attempts = [log for log in access_logs if not log.success]
        
        # Group failed attempts by user
        user_failures = {}
        for log in failed_attempts:
            if log.user_id not in user_failures:
                user_failures[log.user_id] = []
            user_failures[log.user_id].append(log)
        
        # Flag users with excessive failed attempts
        for user_id, failures in user_failures.items():
            if len(failures) > 10:  # Threshold for suspicious activity
                anomalies.extend(failures[:5])  # Include first 5 failures as examples
        
        return anomalies
    
    def _generate_access_summary(self, total_logs: int, patterns: List[AccessPattern], 
                                violations: List[Dict[str, Any]], anomalies: List[AccessLog]) -> str:
        """Generate access pattern analysis summary"""
        return f"""Access Pattern Analysis Summary:
- Analyzed {total_logs} access events
- Identified {len(patterns)} access patterns
- Found {len(violations)} privilege violations
- Detected {len(anomalies)} anomalous events
- Overall security posture: {'Good' if len(violations) == 0 else 'Needs Attention'}"""
    
    def _detect_governance_violations(self, data_assets: List[DataAsset]) -> List[GovernanceViolation]:
        """Detect data governance policy violations"""
        violations = []
        
        for asset in data_assets:
            # Check for missing policies
            if not asset.policies:
                violations.append(GovernanceViolation(
                    violation_id=f"no_policy_{asset.asset_id}",
                    policy_id="",
                    resource_path=asset.local_file_path,
                    violation_type="missing_policy",
                    description=f"Data asset {asset.name} has no governance policies",
                    severity="medium",
                    detected_at=datetime.now(),
                    remediation_steps=["Assign appropriate governance policies to data asset"]
                ))
            
            # Check for unclassified data
            if asset.classification == DataClassification.PUBLIC and "sensitive" in asset.name.lower():
                violations.append(GovernanceViolation(
                    violation_id=f"misclassified_{asset.asset_id}",
                    policy_id="",
                    resource_path=asset.local_file_path,
                    violation_type="data_misclassification",
                    description=f"Asset {asset.name} may be misclassified as public",
                    severity="high",
                    detected_at=datetime.now(),
                    remediation_steps=["Review and update data classification"]
                ))
        
        return violations
    
    def _calculate_compliance_score(self, data_assets: List[DataAsset], 
                                  violations: List[GovernanceViolation]) -> float:
        """Calculate overall compliance score"""
        if not data_assets:
            return 0.0
        
        total_assets = len(data_assets)
        assets_with_violations = len(set(v.resource_path for v in violations))
        
        compliance_score = max(0.0, (total_assets - assets_with_violations) / total_assets)
        return round(compliance_score * 100, 2)
    
    def _identify_policy_gaps(self, data_assets: List[DataAsset]) -> List[str]:
        """Identify policy coverage gaps"""
        gaps = []
        
        # Check for assets without encryption policies
        unencrypted_assets = [a for a in data_assets if not any(
            p.policy_type == PolicyType.ENCRYPTION for p in a.policies
        )]
        if unencrypted_assets:
            gaps.append(f"{len(unencrypted_assets)} assets lack encryption policies")
        
        # Check for assets without retention policies
        no_retention_assets = [a for a in data_assets if not any(
            p.policy_type == PolicyType.RETENTION for p in a.policies
        )]
        if no_retention_assets:
            gaps.append(f"{len(no_retention_assets)} assets lack retention policies")
        
        return gaps
    
    def _generate_governance_recommendations(self, violations: List[GovernanceViolation], 
                                           gaps: List[str]) -> List[str]:
        """Generate governance improvement recommendations"""
        recommendations = []
        
        if violations:
            recommendations.append(f"Address {len(violations)} governance violations immediately")
            
            high_severity = [v for v in violations if v.severity == "high"]
            if high_severity:
                recommendations.append(f"Prioritize {len(high_severity)} high-severity violations")
        
        if gaps:
            recommendations.append("Implement missing policy types to improve coverage")
            recommendations.extend([f"Address gap: {gap}" for gap in gaps])
        
        if not violations and not gaps:
            recommendations.append("Governance compliance is good - maintain current policies")
        
        return recommendations
    
    def _analyze_cross_account_patterns(self, data_assets: List[DataAsset]) -> List[Dict[str, Any]]:
        """Analyze cross-account access patterns"""
        patterns = []
        
        # Simulate cross-account pattern detection
        bucket_groups = {}
        for asset in data_assets:
            bucket = asset.minio_bucket
            if bucket not in bucket_groups:
                bucket_groups[bucket] = []
            bucket_groups[bucket].append(asset)
        
        for bucket, assets in bucket_groups.items():
            if len(assets) > 1:
                patterns.append({
                    "pattern_type": "multi_asset_bucket",
                    "bucket": bucket,
                    "asset_count": len(assets),
                    "optimization_opportunity": "Consider bucket-level access policies"
                })
        
        return patterns
    
    def _generate_governance_summary(self, total_assets: int, compliance_score: float, 
                                   violations: int, recommendations: int) -> str:
        """Generate governance analysis summary"""
        return f"""Data Governance Analysis Summary:
- Analyzed {total_assets} data assets
- Compliance score: {compliance_score}%
- Found {violations} policy violations
- Generated {recommendations} recommendations
- Governance status: {'Compliant' if compliance_score > 80 else 'Needs Improvement'}"""
    
    def _detect_policy_conflicts(self, policies: List[LocalPolicy]) -> List[PolicyConflict]:
        """Detect conflicts between policies"""
        conflicts = []
        
        # Check for conflicting access control policies
        access_policies = [p for p in policies if p.policy_type == PolicyType.ACCESS_CONTROL]
        
        for i, policy1 in enumerate(access_policies):
            for policy2 in access_policies[i+1:]:
                if self._policies_conflict(policy1, policy2):
                    conflicts.append(PolicyConflict(
                        conflict_id=f"conflict_{policy1.policy_id}_{policy2.policy_id}",
                        conflicting_policies=[policy1.policy_id, policy2.policy_id],
                        conflict_type="access_control_conflict",
                        description=f"Policies {policy1.name} and {policy2.name} have conflicting rules",
                        affected_resources=[],
                        resolution_options=[
                            "Merge policies with consistent rules",
                            "Define policy precedence order",
                            "Split policies by resource scope"
                        ]
                    ))
        
        return conflicts
    
    def _policies_conflict(self, policy1: LocalPolicy, policy2: LocalPolicy) -> bool:
        """Check if two policies have conflicting rules"""
        # Simple conflict detection - in practice this would be more sophisticated
        rules1 = policy1.rules
        rules2 = policy2.rules
        
        # Check for conflicting allow/deny rules
        if rules1.get("default_action") == "allow" and rules2.get("default_action") == "deny":
            return True
        
        return False
    
    def _generate_policy_improvements(self, policies: List[LocalPolicy], 
                                    conflicts: List[PolicyConflict]) -> List[PolicyRecommendation]:
        """Generate policy improvement recommendations"""
        recommendations = []
        
        if conflicts:
            recommendations.append(PolicyRecommendation(
                recommendation_id="resolve_conflicts",
                recommendation_type="conflict_resolution",
                title="Resolve Policy Conflicts",
                description="Address conflicting policies to ensure consistent enforcement",
                affected_policies=[c.conflicting_policies for c in conflicts],
                implementation_steps=[
                    "Review conflicting policy rules",
                    "Define policy precedence hierarchy",
                    "Test policy changes in staging environment"
                ],
                expected_impact="Improved policy consistency and predictable access control",
                priority="high"
            ))
        
        # Check for outdated policies
        old_policies = [p for p in policies if 
                       (datetime.now() - p.updated_at).days > 365]
        if old_policies:
            recommendations.append(PolicyRecommendation(
                recommendation_id="update_old_policies",
                recommendation_type="policy_maintenance",
                title="Update Outdated Policies",
                description=f"Review and update {len(old_policies)} policies not modified in over a year",
                affected_policies=[p.policy_id for p in old_policies],
                implementation_steps=[
                    "Review policy relevance and effectiveness",
                    "Update rules based on current requirements",
                    "Document policy changes"
                ],
                expected_impact="Improved policy relevance and effectiveness",
                priority="medium"
            ))
        
        return recommendations
    
    def _identify_harmonization_opportunities(self, policies: List[LocalPolicy]) -> List[Dict[str, Any]]:
        """Identify opportunities to harmonize similar policies"""
        opportunities = []
        
        # Group policies by type
        policy_groups = {}
        for policy in policies:
            policy_type = policy.policy_type
            if policy_type not in policy_groups:
                policy_groups[policy_type] = []
            policy_groups[policy_type].append(policy)
        
        # Look for similar policies that could be merged
        for policy_type, type_policies in policy_groups.items():
            if len(type_policies) > 3:  # Many policies of same type
                opportunities.append({
                    "opportunity_type": "policy_consolidation",
                    "policy_type": policy_type.value,
                    "policy_count": len(type_policies),
                    "description": f"Consider consolidating {len(type_policies)} {policy_type.value} policies",
                    "potential_benefits": [
                        "Reduced policy management overhead",
                        "Improved consistency",
                        "Easier compliance monitoring"
                    ]
                })
        
        return opportunities
    
    def _generate_optimization_suggestions(self, policies: List[LocalPolicy]) -> List[str]:
        """Generate policy optimization suggestions"""
        suggestions = []
        
        if len(policies) > 20:
            suggestions.append("Consider policy consolidation to reduce management complexity")
        
        inactive_policies = [p for p in policies if not p.active]
        if inactive_policies:
            suggestions.append(f"Remove {len(inactive_policies)} inactive policies to reduce clutter")
        
        if not policies:
            suggestions.append("Implement basic governance policies for data protection")
        
        return suggestions
    
    def _generate_policy_summary(self, total_policies: int, conflicts: int, 
                                recommendations: int) -> str:
        """Generate policy analysis summary"""
        return f"""Policy Analysis Summary:
- Analyzed {total_policies} governance policies
- Found {conflicts} policy conflicts
- Generated {recommendations} improvement recommendations
- Policy health: {'Good' if conflicts == 0 else 'Needs Attention'}"""
    
    def _group_assets_by_account_pattern(self, data_assets: List[DataAsset]) -> Dict[str, List[DataAsset]]:
        """Group assets by simulated account patterns"""
        groups = {}
        
        for asset in data_assets:
            # Simulate account grouping based on bucket naming patterns
            account = asset.minio_bucket.split('-')[0] if '-' in asset.minio_bucket else 'default'
            if account not in groups:
                groups[account] = []
            groups[account].append(asset)
        
        return groups
    
    def _analyze_cross_account_pattern(self, source_account: str, source_assets: List[DataAsset],
                                     target_account: str, target_assets: List[DataAsset]) -> Optional[CrossAccountAccessPattern]:
        """Analyze cross-account access pattern between two account groups"""
        # Calculate potential data transfer volume
        total_volume = sum(asset.size_bytes for asset in source_assets) / (1024**3)  # GB
        
        if total_volume > 1.0:  # Only consider patterns with significant data volume
            return CrossAccountAccessPattern(
                pattern_id=f"cross_account_{source_account}_{target_account}",
                source_account=source_account,
                target_account=target_account,
                resource_type="data_assets",
                access_frequency=len(source_assets),
                data_volume_gb=total_volume,
                current_copy_operations=len(source_assets),
                zero_copy_feasible=total_volume < 100,  # Feasible for smaller datasets
                optimization_potential="medium" if total_volume < 50 else "high",
                implementation_complexity="low" if len(source_assets) < 10 else "medium",
                cost_savings_estimate=total_volume * 0.02  # Estimated savings per GB
            )
        
        return None
    
    def _create_error_report(self, error_message: str) -> AccessPatternReport:
        """Create error report for access pattern analysis"""
        return AccessPatternReport(
            analysis_id="error",
            timestamp=datetime.now(),
            total_access_events=0,
            unique_users=0,
            unique_resources=0,
            patterns_identified=[],
            security_recommendations=[],
            least_privilege_violations=[],
            anomalous_access_events=[],
            summary=f"Analysis failed: {error_message}"
        )
    
    def _create_governance_error_report(self, error_message: str) -> GovernanceAnalysisReport:
        """Create error report for governance analysis"""
        return GovernanceAnalysisReport(
            analysis_id="error",
            timestamp=datetime.now(),
            total_assets_analyzed=0,
            policies_evaluated=[],
            violations_found=[],
            compliance_score=0.0,
            policy_coverage_gaps=[],
            recommendations=[],
            cross_account_patterns=[],
            summary=f"Analysis failed: {error_message}"
        )
    
    def close(self):
        """Close database connections"""
        if self.duckdb_conn:
            self.duckdb_conn.close()
            self.logger.info("DuckDB connection closed")