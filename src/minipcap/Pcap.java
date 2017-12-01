/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package minipcap;
import java.io.IOException;
import java.nio.charset.Charset;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
/**
 *
 * @author Hacked By Chen
 */
public class Pcap {
    //获得所有网卡列表
    NetworkInterface[] devices = JpcapCaptor.getDeviceList();
    //前端界面输出信息流
    StringBuffer sb = new StringBuffer();
    String[][] desc = new String[10][10];
    double t; 
    Object getNetworkInterface(){ 
        System.out.println("/***获取网络接口设备*****/");
        /*输出网卡信息*/
        for(int i=0;i<devices.length;i++){
            String s = (devices[i].description == null?devices[i].name:(devices[i].name+"    "+devices[i].description));
            sb.append("网卡"+(i+1)+": "+s+"\n");
        }
        return sb;
    }
    NetworkInterface[] getDevices(){
        return devices; 
        }
    /* 获得所有网卡返回给下拉菜单 */
    String[] getDevicesInfo(){
        String[] itemList = new String[devices.length];
        for(int i=0;i<getDevicesNum();i++){
            itemList[i]=devices[i].name+"     "+devices[i].description;
        }
        return itemList;
    }
    int getDevicesNum(){
        return devices.length;
    }
    String[][] getDesc(){
        return desc;
    }
//    double getRunTime(){
//        return t;
//    }
    double T1 = System.currentTimeMillis();
    StringBuffer getIPpacket(int k){
        JpcapCaptor jpcap = null;
	int caplen = 1512;
	boolean promiscCheck = true;	
	try{
            jpcap = JpcapCaptor.openDevice(devices[k], caplen, promiscCheck, 50);
	}catch(IOException e){
            e.printStackTrace();
	}
        /*----------第二步抓包-----------------*/
	int i = 0;
        //double t1=System.currentTimeMillis();
        while(i <9)  
        {  
            Packet packet  = jpcap.getPacket();
            if(packet instanceof IPPacket)  
            {
		i++;
		IPPacket ip = (IPPacket)packet;//强转
                sb.append("版本：IPv4\n");
		sb.append("优先权：" + ip.priority+"\n");
                sb.append("区分服务：最大的吞吐量： " + ip.t_flag+"\n");
		sb.append("区分服务：最高的可靠性：" + ip.r_flag+"\n");
		sb.append("长度：" + ip.length+"\n");
                sb.append("标识：" + ip.ident+"\n");
                sb.append("DF:Don't Fragment: " + ip.dont_frag+"\n");
                sb.append("NF:Nore Fragment: " + ip.more_frag+"\n");
                sb.append("片偏移：" + ip.offset+"\n");
                sb.append("生存时间："+ ip.hop_limit+"\n");

                String protocol ="";
                switch(new Integer(ip.protocol))
                {
                case 1:protocol = "ICMP";break;
                case 2:protocol = "IGMP";break;
                case 6:protocol = "TCP";break;
                case 8:protocol = "EGP";break;
                case 9:protocol = "IGP";break;
                case 17:protocol = "UDP";break;
                case 41:protocol = "IPv6";break;
                case 89:protocol = "OSPF";break;
                default : break;
                }
                sb.append("协议：" + protocol+"\n");
                sb.append("源IP " + ip.src_ip.getHostAddress()+"\n");
                sb.append("目的IP " + ip.dst_ip.getHostAddress()+"\n");
                sb.append("源主机名： " + ip.src_ip+"\n");
                
                sb.append("目的主机名： " + ip.dst_ip+"\n");
                sb.append("包详细信息"+packet+"\n");
                sb.append("+----------------------------------------------+\n");
                desc[i][0]="IPv4   "+protocol;
                desc[i][1]=ip.src_ip.getHostAddress();
                desc[i][2]=ip.dst_ip.getHostAddress();
                desc[i][3]=" "+packet;
                desc[i][4]=" "+ip.length;
                desc[i][5]=ip.src_ip.getHostAddress();
                desc[i][6]=ip.dst_ip.getHostAddress();
                desc[i][7]=""+ip.src_ip;
                desc[i][8]=""+ip.dst_ip;
                String s = new String(((IPPacket) packet).data,Charset.forName("UTF-8"));
                desc[i][9]=s;
            }
	}
	return sb;
}
   // double T2 = System.currentTimeMillis();
}




