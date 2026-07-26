# 🚀 Release Notes / Список изменений

<p align="center">
  <a href="#english"><img src="https://img.shields.io/badge/Language-English-blue?style=for-the-badge&logo=github" alt="English"/></a>
  <a href="#русский"><img src="https://img.shields.io/badge/Язык-Русский-red?style=for-the-badge&logo=github" alt="Русский"/></a>
</p>

---

## English

### 📦 Key Features & Updates
* **💻 Multi-Platform Compilation:** Full support added for **Windows x64**, **Linux x64**, and **ARM64** architectures.
* **🛠️ Stability Improvements:** Various minor fixes and under-the-hood optimization.

---

### 🧷 1. Asynchronous SOCKS5 Proxy Support
Integrated a dedicated proxy class for seamless, fully asynchronous connections to SOCKS5 proxy servers.

```cpp
#include <thread>
#include "RakNet/SOCKS5.hpp"

// Initialize proxy instance
SOCKS5::SOCKS5* prx = new SOCKS5::SOCKS5();

void OnSocks5Error(SOCKS5::SOCKS5* proxy, SOCKS5::eSocks5Error error)
{
   if(proxy->IsStarted() && error == SOCKS5::eSocks5Error::eProxyInitializedSuccessfully)
   {
      printf("Proxy started successfully.\n");
   }
}

int main()
{
   // Setup and start connection
   prx->RegisterHandler(OnSocks5Error);
   prx->Start("ProxyHost", "ProxyPort", "ProxyLogin", "ProxyPassword");
    
   // Main update loop
   while (true)
   {
      prx->Update();
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
   }

   delete prx;
   return 0;  
}
```

---

### 🤖 2. Unified Incoming RPC Handler
Implemented a centralized handler to manage incoming Remote Procedure Calls (RPC) efficiently.

```cpp
#include <thread>
#include "RakNet/RakNetworkFactory.h"
#include "RakNet/RakClientInterface.h"

void RPCHandler(std::uint64_t botId, std::int32_t rpcId, RakNet::BitStream bs, RakPeerInterface* pRakPeer)
{
   if(botId == 1337) // 1337 - Target Bot ID
   {
       /*
           ... Your custom logic here ...
       */
   }
}

int main()
{
   RakClientInterface* client = RakNetworkFactory::GetRakClientInterface();
   /*
       ... Initialization ...
   */
   client->RegisterRPCHandle(RPCHandler, 1337);
    
   return 0;  
}    
```

⚡ [Back to top / Наверх](#-release-notes--список-изменений)

---

## Русский

### 📦 Главные изменения
* **💻 Кроссплатформенность:** Добавлена компиляция под **Windows x64**, **Linux x64** и **ARM64**.
* **🛠️ Повешение стабильности:** Проведены мелкие багфиксы и оптимизация кода.

---

### 🧷 1. Поддержка асинхронного SOCKS5 Прокси
Добавлен класс прокси для полноценной работы с SOCKS5 серверами. Подключение происходит полностью в асинхронном режиме, не блокируя основной поток.

```cpp
#include <thread>
#include "RakNet/SOCKS5.hpp"

// Создание экземпляра прокси
SOCKS5::SOCKS5* prx = new SOCKS5::SOCKS5();

void OnSocks5Error(SOCKS5::SOCKS5* proxy, SOCKS5::eSocks5Error error)
{
   if(proxy->IsStarted() && error == SOCKS5::eSocks5Error::eProxyInitializedSuccessfully)
   {
      printf("Успешное подключение к прокси.\n");
   }
}

int main()
{
   // Регистрация колбэка и запуск
   prx->RegisterHandler(OnSocks5Error);
   prx->Start("ProxyHost", "ProxyPort", "ProxyLogin", "ProxyPassword");
    
   // Основной цикл обновления
   while (true)
   {
      prx->Update();
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
   }

   delete prx;
   return 0;  
}
```

---

### 🤖 2. Единый обработчик входящих RPC
Реализована централизованная система перехвата и обработки входящих удаленных вызовов процедур (RPC).

```cpp
#include <thread>
#include "RakNet/RakNetworkFactory.h"
#include "RakNet/RakClientInterface.h"

void RPCHandler(std::uint64_t botId, std::int32_t rpcId, RakNet::BitStream bs, RakPeerInterface* pRakPeer)
{
   if(botId == 1337) // 1337 - ID бота
   {
       /*
           ... Ваша логика обработки ...
       */
   }
}

int main()
{
   RakClientInterface* client = RakNetworkFactory::GetRakClientInterface();
   /*
       ... Инициализация ...
   */
   client->RegisterRPCHandle(RPCHandler, 1337);
    
   return 0;  
}    
```

⚡ [Back to top / Наверх](#-release-notes--список-изменений)