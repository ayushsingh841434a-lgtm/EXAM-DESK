import { PrismaClient, Role, UserStatus, TestStatus } from '@prisma/client';
import bcrypt from 'bcryptjs';
const p=new PrismaClient();
async function main(){
 const email=(process.env.ADMIN_EMAIL||'admin@example.com').trim().toLowerCase(); const pass=process.env.ADMIN_PASSWORD||'Admin12345!';
 const hash=await bcrypt.hash(pass,12);
 await p.user.upsert({where:{email},update:{passwordHash:hash,role:Role.ADMIN,status:UserStatus.ACTIVE,emailVerified:true},create:{name:'Administrator',email,passwordHash:hash,role:Role.ADMIN,status:UserStatus.ACTIVE,emailVerified:true}});
 let test=await p.test.findFirst({where:{title:'Demo Exam'}});
 if(!test){ test=await p.test.create({data:{title:'Demo Exam',description:'Sample test. Edit or replace this from the admin panel.',duration:30,status:TestStatus.LIVE,startTime:new Date(Date.now()-3600000),endTime:new Date(Date.now()+86400000),violationLimit:3,maxAttempts:1}});
  const qs=[['What does CPU stand for?',['Central Processing Unit','Computer Personal Unit','Central Program Utility','Control Processing User'],0],['Which protocol is used for secure web browsing?',['HTTP','FTP','HTTPS','SMTP'],2],['What is 2 + 2?',['3','4','5','6'],1]] as const;
  for(let i=0;i<qs.length;i++){const q=qs[i]; await p.question.create({data:{testId:test.id,questionText:q[0],marks:1,order:i,options:{create:q[1].map((x,j)=>({optionText:x,isCorrect:j===q[2],order:j}))}}});}
 }
 console.log('Admin:',email,'Password:',pass,'Demo test:',test.id);
}
main().finally(()=>p.$disconnect());
