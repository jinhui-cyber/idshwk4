global total: table[addr] of int=table();
global num_404: table[addr] of int=table();
global url: table[addr] of set[string]=table();
global last_time: time =double_to_time(0);
global now_time:time =double_to_time(0);
event http_reply(C:connection ,Version:string, code:count ,reason:string)
{
	if(last_time==double_to_time(0))
		last_time=current_time();
	if(C$id$orig_h in total){
		++total[C$id$orig_h];
	}
	else{
		total[C$id$orig_h]=1;
	}
	if(code==404){
		if(C$id$orig_h in num_404){
			++num_404[C$id$orig_h];
		}
		else{
			num_404[C$id$orig_h]=1;
		}
		if(C$id$orig_h in url){
			add url[C$id$orig_h][C$http$uri];
		}
		else{
			url[C$id$orig_h]=set(C$http$uri);
		}
	}
	now_time=current_time();
	if(now_time-last_time>=10mins){
		last_time=now_time;
		for(i in num_404){
			if(num_404[i]>2)
				if(num_404[i]/total[i]>=0.2)
					if(|url[i]|/num_404[i]>0.5){
						print i,"is a scanner with ",num_404[i]," scan attemps on ",|url[i]|," urls";
					}
		}
	}
}
event zeek_done()
	{
	}
