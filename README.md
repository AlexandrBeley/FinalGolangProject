# FinalGolangProject
Для старта нужно запустить main01.go
В выражении могут быть (, ), *, /, +, -
Ответ округляется до целых

Для регистрации:
http://localhost:1229/register/?user=<имя_пользователя>&password=<пароль>
вывод - Ваш токен на 5 минут

Для получения токена:
http://localhost:1229/login/?user=<имя_пользователя>&password=<пароль>
вывод - Ваш токен на 5 минут

для ввода выражения 
http://localhost:1229/?nm=<выражение_для_счёта>&token=<Ваш_токен>
http://localhost:1229/?nm=4*(2+77)&token=<Ваш_токен>
вывод - id запроса

Для получения результата обработки 
http://localhost:1229/get/?id=<id_запроса>&token=<Ваш_токен>

Для получения всех сведений об обработке 
http://localhost:1229/data/?token=<Ваш_токен>

Для изменения времени операций 
http://localhost:1229/times/?timePlus=300ms&timeMinus=100s&timeDivis=15s&timeMult=11s
timePlus - время сложения, timeMinus - время вычитания, timeDivis - время деления, timeMult - время умножения

@Jdoalak
