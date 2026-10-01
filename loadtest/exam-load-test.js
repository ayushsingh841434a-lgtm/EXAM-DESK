import http from 'k6/http'; import {check,sleep} from 'k6'; import {SharedArray} from 'k6/data';
export const options={scenarios:{students:{executor:'constant-vus',vus:Number(__ENV.VUS||1000),duration:__ENV.DURATION||'30s'}}};
const base=__ENV.BASE_URL||'http://localhost:8080'; export default function(){const email=`load-${__VU}@example.com`;const login=http.post(base+'/api/auth/login',JSON.stringify({email,password:__ENV.PASSWORD||'Test12345!'}),{headers:{'Content-Type':'application/json'}});check(login,{login:'status is 200/401/403'});sleep(1)}
