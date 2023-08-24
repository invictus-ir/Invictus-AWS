CREATE EXTERNAL TABLE IF NOT EXISTS yourtable (
        
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://yourpath/'  