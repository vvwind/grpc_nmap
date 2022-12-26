***Simple grpc nmap service***

> ## Зависимости.
> 
> github.com/Ullaakut/nmap v2.0.2+incompatible
> 
> github.com/golang/protobuf v1.5.2
> 
> google.golang.org/grpc v1.51.0
> Замена скрипта для nmap
> https://github.com/vulnersCom/nmap-vulners


**Сервер и клиент работают на localhost:9000**

**Запуск сервера**
![image](https://user-images.githubusercontent.com/106326324/209542911-28963758-c43f-45dd-8bcf-ee68b0f7f807.png)
**Запуск клиента**
![image](https://user-images.githubusercontent.com/106326324/209542934-3f233919-46ae-4b6c-ad94-7b05ec33a3eb.png)

**Параметра запроса клиента в cmd/client/client.go**
![image](https://user-images.githubusercontent.com/106326324/209543120-0925dcc0-8a24-4d60-8bf3-8311f5d5aa02.png)

Результат работы программы, вывод client
![image](https://user-images.githubusercontent.com/106326324/209543171-c352041c-617c-4225-9eb3-9dd43606e0cc.png)

Результат работы программы, вывод server
![image](https://user-images.githubusercontent.com/106326324/209543190-abf323a4-f282-490c-bf87-41d35853de09.png)

Структура Makefile
![image](https://user-images.githubusercontent.com/106326324/209543366-c8bf644f-9d9b-43e3-809f-1902a1f246dd.png)

test - запуск тестов
lint - запуск линтера

Так же, тесты запускаются: go test pkg/vulners_test.go
