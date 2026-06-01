"""Tests for the ADO.NET / JDBC SQL connection-string detector."""

from __future__ import annotations

import unittest

from keyleak.detectors import find_detector
from keyleak.local_scanner import scan_text


class DotnetSqlConnectionStringTests(unittest.TestCase):
    def setUp(self):
        self.detector = find_detector("leak.dotnet_sql_connection_string")
        self.assertIsNotNone(self.detector)

    def _types(self, text):
        return [f.type for f in scan_text(text, "appsettings.config", [self.detector])]

    def test_flags_ado_net_sa_string(self):
        text = "Server=tcp:mssql.example.net,1433;Initial Catalog=prod;User ID=sa;Password=S3cr3tP@ss!;"
        self.assertIn("dotnet_sql_connection_string", self._types(text))

    def test_flags_data_source_pwd_string(self):
        text = "Data Source=db1;Initial Catalog=app;User Id=svc;Pwd=Hk29Wq7mZ4;"
        self.assertIn("dotnet_sql_connection_string", self._types(text))

    def test_flags_jdbc_sqlserver_string(self):
        text = "jdbc:sqlserver://db.example.net:1433;databaseName=app;user=sa;password=Adm1n2026X"
        self.assertIn("dotnet_sql_connection_string", self._types(text))

    def test_ignores_connection_string_without_password(self):
        text = "Server=tcp:db.example.net,1433;Initial Catalog=app;Integrated Security=true;"
        self.assertEqual(self._types(text), [])

    def test_ignores_plain_env_password(self):
        # A bare password assignment is not a connection string.
        text = "DB_PASSWORD=hunter2hunter2"
        self.assertEqual(self._types(text), [])

    def test_severity_and_pack(self):
        self.assertEqual(self.detector.severity, "critical")
        self.assertEqual(self.detector.pack, "leak")
        self.assertEqual(self.detector.validation_status, "validated")


if __name__ == "__main__":
    unittest.main()
