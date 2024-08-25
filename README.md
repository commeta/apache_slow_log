##  Описание скрипта apache_slow_log.py

Этот скрипт анализирует логи Apache для выявления самых медленных запросов к серверу. Он извлекает информацию о запросах из конфигурационных файлов, находит соответствующие логи и создает список из 100 самых медленных запросов на основе времени ответа сервера, записанного в микросекундах.

### Функциональность
1. **Получение логов**: Скрипт ищет все файлы конфигурации Apache, содержащие директиву CustomLog, чтобы определить, где находятся файлы логов.
2. **Парсинг логов**: Каждая строка лога анализируется для извлечения IP-адреса и времени выполнения запроса.
3. **Извлечение домена**: Извлекается домен из пути к файлу лога.
4. **Поиск топовых запросов**: Скрипт собирает данные о запросах и сохраняет только 100 самых медленных, используя структуру данных heapq для эффективного управления памятью.
5. **Объединение данных**: Скрипт сравнивает новые данные с уже существующими в slow.log, обновляя записи, если новые запросы медленнее старых.
6. **Запись в файл**: Результаты сохраняются в файл slow.log.

### Формат времени
Время выполнения запросов записывается в микросекундах. Для перевода этого значения в секунды, используйте следующую формулу:

Время (в секундах) = Время (в микросекундах) / 1,000,000


### Пример результата
Результат выполнения скрипта может выглядеть следующим образом:
- 5385806 site1.ru/
- 5315441 site2.ru/1.html
- 4991294 site3.ru/
- 4703806 site1.ru/3.html
- 4699142 site1.ru/10.html


### Установка и использование
1. Скопируйте скрипт на сервер с установленным Python 3.
2. Убедитесь, что у вас есть доступ к логам Apache.
3. Настройте переменные LOG_FILES_GLOB и SLOW_LOG_PATH при необходимости.
4. Запустите скрипт:
   
`python3 apache_slow_log.py`
   

### Зависимости
- Python 3
- Библиотеки стандартной библиотеки: os, re, heapq


### Описание параметра %D в конфигурации формата лога Apache (LogFormat)

- **%D**: Этот параметр выводит время, затраченное на обработку запроса, в микросекундах. Это значение включает все этапы обработки запроса, включая время, затраченное на выполнение кода приложения и время, необходимое для передачи ответа клиенту.

### Пример формата лога

В вашем примере формат лога выглядит следующим образом:

LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined


Здесь:
- %a: IP-адрес клиента.
- %l: Логин клиента (обычно -).
- %u: Имя пользователя (если аутентификация используется).
- %t: Время запроса.
- %r: Запрос, который был выполнен (например, GET /index.html HTTP/1.1).
- %>s: Код состояния HTTP.
- %b: Размер ответа в байтах.
- %{Referer}i: Заголовок Referer из запроса.
- %{User-Agent}i: Заголовок User-Agent из запроса.
- %D: Время выполнения запроса в микросекундах.

### Как это связано со скриптом

1. **Парсинг логов**: Скрипт apache_slow_log.py читает строки из логов Apache с форматом, указанным выше. При парсинге он ищет значение %D, чтобы определить, сколько времени потребовалось для обработки каждого запроса.

2. **Анализ медленных запросов**: Скрипт собирает данные о всех запросах и их времени выполнения, чтобы составить список из 100 самых медленных. Поскольку %D предоставляет время выполнения в микросекундах, скрипт может легко сравнивать и сортировать эти значения.

3. **Сохранение результатов**: После анализа скрипт сохраняет результаты в файл slow.log, где указаны самые медленные запросы, что позволяет администраторам сервера быстро идентифицировать проблемные участки и оптимизировать производительность.

Таким образом, параметр %D является ключевым элементом для работы скрипта, так как он предоставляет необходимую информацию о времени обработки запросов, позволяя эффективно выявлять и анализировать медленные запросы к серверу.


### Лицензия
Этот проект лицензирован под MIT License. 

---

Скрипт предназначен для администраторов серверов, желающих оптимизировать производительность своих веб-приложений путем анализа медленных запросов.
