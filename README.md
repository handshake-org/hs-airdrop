# Handshake 空投

给各位hacker分享一个空投福利，[Handshake](https://handshake.org/) 硬核福利发车了，你有可能领取到`4,246.994314` 枚HNS，目前大概价值 $600，价格一直在变动，各位抓紧哦。

有想具体了解Handshake的，请看[什么是Handshake](https://www.chainnews.com/articles/452340854508.htm)。

既然这么有缘分，大家github互粉下吧，也请关注我们的公众号，谢谢大家。
> <img src="./images/wx.jpg" width="300">

## 符合条件

以下条件必须都符合的，有一定几率领取到`4,246.994314` 枚HNS，没有发现截止时间。

- `2019-02-04`以前，github已经绑定好ssh key的

- `2019-02-04`以前，有15个以上 GitHub 好友的

## 如何自己操作：

1. 去[namebase](https://www.namebase.io/register) 注册一个账户

2. 得到一个hns钱包地址

去[namebase的dashboard](https://www.namebase.io/dashboard)，得到地址 `hs1q......`。
> <img src="./images/addr.png" width="300">

3. 下载 hs-airdrop

clone项目 `git clone https://github.com/rebase-network/hs-airdrop`

进入目录安装依赖，执行 `npm install`。

如果有提示`node-gyp rebuild`，需要先安装 `npm install node-gyp`，再执行 `npm install`。

> <img src="./images/gyp.png" width="600">

4. 如何验证中奖

进入到项目根目录，执行 `./bin/hs-airdrop ~/.ssh/id_rsa hs1q......`

`~/.ssh/id_rsa` 是你的github ssh的私钥文件，是私钥，不要用ssh公钥，也不要用钱包地址的私钥，`hs1q......` 是之前得到的hns地址

有`not find nonce`提示，表示**没中奖**
>![](images/noaward.jpg)

有`Found nonce!`提示，表示**中奖了**，恭喜恭喜！
>![](images/award.jpg)

5. 中奖后，需要把币发送的刚申请的hns地址

在上一步中，验证是否中奖的过程中，如果中奖了会有很多输出内容，并提示 `hsd-rpc sendrawairdrop "base64-string"`
> <img src="./images/sendrawairdrop.png" width="600">

去 [https://www.namebase.io/airdrop](https://www.namebase.io/airdrop)，鼠标滚到最下面，把生成的 `base64-string` 填入进去，然后点击submit。如下图所示。

> <img src="./images/airdrop.png" width="600">

然后去 [hnscan](https://hnscan.com/) 查看转账记录。

6. 等待到账

大概需要16～24个小时才能到账，也许会更长 :cry:
>![](images/tx.png)

7. 验证个人身份

进入 [https://www.namebase.io/verify/](https://www.namebase.io/verify/)，进行 kyc(Know Your Customer)
你可以通过上传 **中国大陆居民身份证件**验证，如果只用一次，可以上传 fake id card，验证时间不需要很长。

8. 交易

去 [https://www.namebase.io/sell](https://www.namebase.io/sell)，请操盘手开始表演。
> <img src="./images/cashout.png" width="600">

## github互粉

1. https://github.com/xrdavies
2. https://github.com/NakaDaoLe
3. https://github.com/h4x3rotab
4. https://github.com/liushooter
5. https://github.com/luckyyang
6. https://github.com/bitrocks
7. https://github.com/dyhbrewer
8. https://github.com/GalaIO
9. https://github.com/bobjiang
10. https://github.com/WannaM
11. https://github.com/Sniper1211