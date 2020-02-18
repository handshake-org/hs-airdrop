# Handshake 空投

## 符合条件

以下条件必须都符合的，才可以领取 `4,246.994314` 枚HNS

- github填写上ssh key的

- 在`2019-02-04`以前有15个以上 GitHub 粉丝的


## 如何代劳

请评估风险


## 如何自己操作：

1. 如何申请hns钱包地址

注册 https://www.namebase.io/dashboard，看截图生成地址，得到地址 `hs1q......`

>![](/images/addr.png)

2. 如何验证中奖

- clone 本项目 `git clone https://github.com/rebase-network/hs-airdrop`

- 进入到 `bin`目录，执行 `./hs-airdrop ~/.ssh/id_rsa hs1q......`

`~/.ssh/id_rsa` 是你的github ssh的私钥，是私钥，不要用公钥，`hs1q......` 是你之前得到的hns地址

有`not find nonce`提示，表示**没中奖**
>![](images/noaward.jpg)

有`Found nonce!`提示，表示**中奖了**，恭喜恭喜！
>![](images/award.jpg)


3. 如何发送交易，获得token


通过https://hnscan.com/ 查看

4. 如何在 https://www.namebase.io/pro kyc

