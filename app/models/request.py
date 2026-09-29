from app.extensions import mongo


class Request:
    @staticmethod
    def to_dict(req):
        return {
            "id": str(req["_id"]),
            "user" : req["user"],
            "timestamp": req["timestamp"], 
            "req_addr":req["req_addr"],
            "method": req["method"],
            "scheme": req["scheme"],
            "path":req["path"],
            "status":req["status"],
            "header":req["header"],
            "data":req["data"],
            "url":req["url"],
            "exception":req["exception"],
        }
