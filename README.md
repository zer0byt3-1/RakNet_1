<!--
EN:
-->

*EN:*
1. Compilation support for Windows x64, Linux x64, and ARM64.
2. Minor fixes
3. Proxy class support for working with a SOCKS5 proxy server, fully asynchronous connection to the server.
```cpp
#include <thread>
#include "RakNet/SOCKS5.hpp"
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
   prx->RegisterHandler(OnSocks5Error);
   prx->Start("ProxyHost", "ProxyPort", "ProxyLogin", "ProxyPassword");
    

   while (true)
   {
      prx->Update();
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
   }

   delete prx;
   return 0;  
}
```
4. Unified incoming RPC handler
```cpp
#include <thread>
#include "RakNet/RakNetworkFactory.h"
#include "RakNet/RakClientInterface.h"

void RPCHandler(std::uint64_t botId, std::int32_t rpcId, RakNet::BitStream bs, RakPeerInterface* pRakPeer)
{
   if(botId == 1337) // 1337 - bot ID
   {
       /*
           ...
       */
   }
}

int main()
{
   RakClientInterface* client = RakNetworkFactory::GetRakClientInterface();
   /*
       ...
   */
   client->RegisterRPCHandle(RPCHandler, 1337);
    
   return 0;  
}    
```
<!--
RU:
-->

*RU:*
1. Поддержка компиляции под Windows x64, Linux x64, ARM64
2. Мелкие фиксы
3. Поддержка прокси класса для работы с SOCKS5 прокси-сервером, полностью асинхронное подключение к серверу
```cpp
#include <thread>
#include "RakNet/SOCKS5.hpp"
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
   prx->RegisterHandler(OnSocks5Error);
   prx->Start("ProxyHost", "ProxyPort", "ProxyLogin", "ProxyPassword");
    

   while (true)
   {
      prx->Update();
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
   }

   delete prx;
   return 0;  
}
```
4. Единый обработчик входящих RPC
```cpp
#include <thread>
#include "RakNet/RakNetworkFactory.h"
#include "RakNet/RakClientInterface.h"

void RPCHandler(std::uint64_t botId, std::int32_t rpcId, RakNet::BitStream bs, RakPeerInterface* pRakPeer)
{
   if(botId == 1337) // 1337 - ID бота
   {
       /*
           ...
       */
   }
}

int main()
{
   RakClientInterface* client = RakNetworkFactory::GetRakClientInterface();
   /*
       ...
   */
   client->RegisterRPCHandle(RPCHandler, 1337);
    
   return 0;  
}    
```
