import jwt


jwt_token = jwt.encode({"some": "payload"}, 'abc123', algorithm='HS256')
token = jwt_token.decode('utf-8')
print(token)