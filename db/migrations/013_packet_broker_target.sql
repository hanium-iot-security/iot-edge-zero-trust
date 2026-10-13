-- NULL preserves unknown historical Broker evidence; no zero backfill.
ALTER TABLE packet_feature_logs ADD COLUMN broker_target_ip TEXT
    CHECK (broker_target_ip IS NULL OR
        (typeof(broker_target_ip) = 'text' AND length(trim(broker_target_ip)) > 0
         AND broker_target_ip = trim(broker_target_ip)));
ALTER TABLE packet_feature_logs ADD COLUMN broker_target_port INTEGER
    CHECK (broker_target_port IS NULL OR
        (typeof(broker_target_port) = 'integer' AND broker_target_port = 1883));
ALTER TABLE packet_feature_logs ADD COLUMN broker_target_syn_count INTEGER
    CHECK (
        (broker_target_ip IS NULL AND broker_target_port IS NULL
         AND broker_target_syn_count IS NULL)
        OR
        (broker_target_ip IS NOT NULL AND broker_target_port IS NOT NULL
         AND broker_target_syn_count IS NOT NULL
         AND typeof(broker_target_syn_count) = 'integer'
         AND broker_target_syn_count >= 0)
    );
