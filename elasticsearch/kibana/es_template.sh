curl --silent --noproxy localhost -XPUT 'http://localhost:9200/_template/alert' -d '
{
    "template": "alert",
    "order": 1,
    "aliases":{"CAR_Alert":{}},
    "mappings": {
        "car_data": {
            "properties":{
                "car_name": {"type": "string"},
                "car_description": {"type": "string"},
                "car_number": {"type": "string"}
            }

        }

    }
}
' 
echo ""
curl --silent --noproxy localhost -XPUT 'http://localhost:9200/_template/sitaware' -d '
{
    "template": "sitaware",
    "order": 1,
    "aliases":{"CAR_Alert":{}},
    "mappings": {
        "car_data": {
            "properties":{
                "car_name": {"type": "string"},
                "car_description": {"type": "string"},
                "car_number": {"type": "string"}
            }

        }

    }
}
' 
echo ""
# Error
curl --silent --noproxy localhost -XPUT 'http://localhost:9200/_template/winevent_system' -d '
{
    "template": "winevent_system*",
    "order": 1,
    "aliases":{"events":{}},
    "mappings": {
        "winevent_system": {
            "properties":{
                "data_model": {
                    "properties": {
                        "fields": {
                            "properties": {
                                "utc_time": { "type" : "date","format" : "strict_date_optional_time||epoch_millis"}
                            }
                        }

                    }

                }
               
            }

        }

    }

}
' 
echo ""
curl --silent --noproxy localhost -XPUT 'http://localhost:9200/_template/winevent_security' -d '
{
    "template": "winevent_security*",
    "order": 1,
    "aliases":{"events":{}},
    "mappings": {
        "winevent_security": {
            "properties":{
                "data_model": {
                    "properties": {
                        "fields": {
                            "properties": {
                                "dest_ip": {"type":"ip"},
                                "dest_port": {"type":"long"},
                                "utc_time": { "type" : "date","format" : "strict_date_optional_time||epoch_millis"}
                                
                            }
                        }

                    }

                }
               
            }

        }

    }
}
' 
echo ""
curl --silent --noproxy localhost -XPUT 'http://localhost:9200/_template/sysmon' -d '
{
    "template": "sysmon*",
    "order": 1,
    "aliases":{"events":{}},
    "mappings": {
        "sysmon": {
            "properties":{
                "data_model": {
                    "properties": {
                        "fields": {
                            "properties": {
                                "ip": {"type":"ip"},
                                "utc_time": { "type" : "date","format" : "strict_date_optional_time||epoch_millis"}
                            }
                        }

                    }

                }
               
            }

        }

    }
}
' 
echo ""
