import pytest
import os
from tempora.config.settings import Config

def test_yaml_config(tmp_path):
    yaml_content = """
tempora:
  threshold:
    min_gap: 120
    max_gap: 300000
  business_hours:
    start: "08:00"
    end: "18:00"
    timezone: "UTC"
    ignore_weekends: true
"""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml_content)

    config = Config.load_from_file(str(config_file))
    assert config.min_gap_threshold == 120
    assert config.max_reasonable_gap == 300000
    assert config.business_hours is not None
    assert config.business_hours.start_time == "08:00"
    assert config.business_hours.ignore_weekends is True

def test_json_config(tmp_path):
    json_content = '{"min_gap_threshold": 90}'
    config_file = tmp_path / "config.json"
    config_file.write_text(json_content)

    config = Config.load_from_file(str(config_file))
    assert config.min_gap_threshold == 90
