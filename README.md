# FinalGolangProject
Проект не закончен в связи со сборами по физике, доделываю.

Для запуска нужно запустить main01.go
Для получения токена:
http://localhost:1229/token/?user=<имя_пользователя>
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

