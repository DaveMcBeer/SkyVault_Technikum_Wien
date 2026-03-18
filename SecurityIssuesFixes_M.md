# Security Fixes Michi
ich beschreibe in diesem File kurz was für Sicherheitsrelevante Themen ich gefixed habe

## Issue: Kein CSRF-Schutz in Formularen #5
Wurde wurch flask-wtf CRSF Protection behoben:

https://flask-wtf.readthedocs.io/en/1.2.x/install/
https://flask-wtf.readthedocs.io/en/0.15.x/csrf/#


Flask WTF wurde zu requirements.txt aufgenommen
``` py
Flask-WTF==Flask-WTF
```

CRSF Protection wurde in app.py eingebaut, dadurch werden in weiterer Folge CRSF Tokens bei den Requests verlangt.
``` py
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```
## Issue: Secret Key ist hart codiert und gefährdet Sessionsicherheit #3

