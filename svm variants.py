import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import seaborn as sns
#print(os.listdir('C:\\Users\\padka\\Downloads\\KDDcup.data'))
with open("C:\\Users\\padka\\Downloads\\KDDcup.data\\kddcup.names",'r') as s:
    print(s.read())
cols=['duration',
'protocol_type',
'service',
'flag',
'src_bytes',
'dst_bytes',
'land',
'wrong_fragment',
'urgent',
'hot',
'num_failed_logins',
'logged_in',
'num_compromised',
'root_shell',
'su_attempted',
'num_root',
'num_file_creations',
'num_shells',
'num_access_files',
'num_outbound_cmds',
'is_host_login',
'is_guest_login',
'count',
'srv_count',
'serror_rate',
'srv_serror_rate',
'rerror_rate',
'srv_rerror_rate',
'same_srv_rate',
'diff_srv_rate',
'srv_diff_host_rate',
'dst_host_count',
'dst_host_srv_count',
'dst_host_same_srv_rate',
'dst_host_diff_srv_rate',
'dst_host_same_src_port_rate',
'dst_host_srv_diff_host_rate',
'dst_host_serror_rate',
'dst_host_srv_serror_rate',
'dst_host_rerror_rate',
'dst_host_srv_rerror_rate']

print(cols)
cols.append('target')
print(cols)
with open("C:\\Users\\padka\\Downloads\\KDDcup.data\\training_attack_types",'r') as s:
    print(s.read())

attack_types={
'normal': 'normal',
'back': 'dos',
'buffer_overflow': 'u2r',
'ftp_write': 'r2l',
'guess_passwd': 'r2l',
'imap': 'r2l',
'ipsweep': 'probe',
'land': 'dos',
'loadmodule': 'u2r',
'multihop': 'r2l',
'neptune': 'dos',
'nmap': 'probe',
'perl': 'u2r',
'phf': 'r2l',
'pod': 'dos',
'portsweep': 'probe',
'rootkit': 'u2r',
'satan': 'probe',
'smurf': 'dos',
'spy': 'r2l',
'teardrop': 'dos',
'warezclient': 'r2l',
'warezmaster': 'r2l'
}

#print(attack_types)
df=pd.read_csv("C:\\Users\\padka\\Downloads\\KDDcup.data\\kddcup.data_10_percent\\kddcup.data_10_percent",names=cols)
df['Attack_Types']=df.target.apply(lambda r: attack_types[r[:-1]])
#print(df.head())
#print(df.shape)
#print(df['target'].value_counts())
#print(df['Attack_Types'].value_counts())
#print(df.dtypes)
#print(df.isnull().sum())
print(df.info())
print(df.describe())
col_num=df._get_numeric_data().columns
categorical_cols=list(set(df.columns)-set(col_num))
categorical_cols.remove('target')
categorical_cols.remove('Attack_Types')
#print(categorical_cols)

df['protocol_type'].value_counts().plot(kind='bar')
df['service'].value_counts().plot(kind='bar',width=0.01)
#df['flag'].value_counts().plot(kind='bar')
df=df.dropna('columns')
corr=df.corr()
print(corr.columns)
plt.figure(figsize=(15,12))
sns.heatmap(corr)
plt.show()

df=df[[c for c in df if df[c].nunique()>1]]
print(df['num_root'].corr(df['num_compromised']))
#print(df['hot'].corr(df['is_guest_login']))
#print(df['srv_count'].corr(df['count']))
print(df['srv_serror_rate'].corr(df['serror_rate']))
#print(df['srv_rerror_rate'].corr(df['rerror_rate']))
#print(df['dst_host_same_srv_rate'].corr(df['dst_host_srv_count']))
print(df['dst_host_srv_serror_rate'].corr(df['dst_host_serror_rate']))
#print(df['dst_host_srv_rerror_rate'].corr(df['dst_host_rerror_rate']))
#print(df['dst_host_same_srv_rate'].corr(df['same_srv_rate']))
#print(df['dst_host_srv_count'].corr(df['same_srv_rate']))
#print(df['dst_host_same_src_port_rate'].corr(df['srv_count']))
print(df['dst_host_serror_rate'].corr(df['serror_rate']))
#print(df['dst_host_serror_rate'].corr(df['srv_serror_rate']))
#print(df['dst_host_srv_serror_rate'].corr(df['serror_rate']))
print(df['dst_host_srv_serror_rate'].corr(df['srv_serror_rate']))
#print(df['dst_host_rerror_rate'].corr(df['rerror_rate']))
#print(df['dst_host_rerror_rate'].corr(df['srv_rerror_rate']))
#print(df['dst_host_srv_rerror_rate'].corr(df['rerror_rate']))
#print(df['dst_host_srv_rerror_rate'].corr(df['srv_rerror_rate']))
#df.drop('dst_host_same_src_port_rate',axis=1,inplace=True)
#df.drop('hot',axis=1,inplace=True)
#df.drop('srv_count',axis=1,inplace=True)
df.drop('srv_rerror_rate',axis=1,inplace=True)
df.drop('dst_host_same_srv_rate',axis=1,inplace=True)
df.drop('dst_host_srv_rerror_rate',axis=1,inplace=True)
#df.drop('dst_host_srv_count',axis=1,inplace=True)
df.drop('dst_host_serror_rate',axis=1,inplace=True)
df.drop('dst_host_srv_serror_rate',axis=1,inplace=True)
df.drop('dst_host_rerror_rate',axis=1,inplace=True)
df.drop('num_root',axis=1,inplace=True)
df.drop('srv_serror_rate',axis=1,inplace=True)

print(df.shape)
print(df.head())
print(df['service'].value_counts())
df.drop('service',axis=1,inplace=True)
proto={'icmp':0,'tcp':1,'udp':2}
flg={'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5,'S1':6,'S2':7,'RSTOS0':8,'S3':9,'OTH':10}
df['flag']=df['flag'].map(flg)
df['protocol_type']=df['protocol_type'].map(proto)

#model building
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score , precision_score , recall_score , f1_score
import time
from sklearn.svm import SVC
from sklearn.metrics import plot_roc_curve , auc
from sklearn.preprocessing import LabelEncoder
from sklearn.multiclass import OneVsRestClassifier

#df['binary_target'] = (df['Attack_Types'] != 'normal').astype(int)
y=df['Attack_Types']
x=df.drop(['target','Attack_Types'],axis=1)
label_encoder=LabelEncoder()
label_encoder.fit(y) 
y=label_encoder.transform(y)
#classes=label_encoder.classes_
#scaler=MinMaxScaler()
x=MinMaxScaler().fit_transform(x)
x_train,x_test,y_train,y_test= train_test_split(x,y,test_size=0.25,random_state=42)
print(x_train.shape,x_test.shape)
print(y_train.shape,y_test.shape)

svm_linear=(SVC(kernel='linear',C=1.0,random_state=42,probability=True))
svm_poly=SVC(kernel='poly',degree=3,C=1.0,random_state=42)
svm_rbdk=SVC(kernel='rbf',C=1.0,gamma='scale',random_state=42)
svm_sigmoid=SVC(kernel='sigmoid',C=1.0,random_state=42)
#training
svm_linear.fit(x_train,y_train)
pred_linear=svm_linear.predict(x_test)
print(pred_linear)
#from sklearn.preprocessing import label_binarize
#y_test_binarized = label_binarize(y_test, classes=np.unique(y_test))


fpr, tpr, thresholds = plot_roc_curve(y_test, pred_linear)
roc_auc = auc(fpr, tpr)
plt.figure(figsize=(8, 8))
plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = {:.2f})'.format(roc_auc))
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.show()
# Plot ROC curves for each class
#plt.figure(figsize=(10, 8))

# Linear kernel
#svm_linear.fit(x_train, y_train)
#y_score_linear = svm_linear.decision_function(x_test)
#fpr_linear, tpr_linear, _ = roc_curve(y_test_binarized[:, 0], pred_linear)
#roc_auc_linear = auc(fpr_linear, tpr_linear)
#plt.plot(fpr_linear, tpr_linear, label=f'Linear Kernel (AUC = {roc_auc_linear:.2f})')



#plotting roc
#from sklearn.preprocessing import label_binarize
#unique_classes=np.unique(y_test)
#y_test_binarized=label_binarize(y_test,classes=unique_classes)

#roc curve for classes
#fpr={}
#tpr={}
#thresh={}
#roc_auc=dict()
#n_class=classes.shape[0]
#for i in range(n_class):
 ##  fpr[i],tpr[i],thresh[i]=roc_curve(y_test_binarized[:,i],pred_linear[:,i])
   # roc_auc[i]=auc(fpr[i],tpr[i])
    #plotting
    #plt.plot(fpr[i],tpr[i],linestyle='--',label='%s vs rest (AUC=%0.2f)'%(classes[i],roc_auc[i]))
#plt.plot([0,1],[0,1],'b--')
#plt.xlim([0,1])
#plt.ylim([0.1,0.5])
#plt.title('ROC linear SVM')
#plt.xlabel('False positive Rate')
#plt.ylabel('True positive rate')
#plt.legend(loc='lower right')
#plt.show()
# Plot the ROC curve for multi-class classification


#fpr, tpr, thresholds = roc_curve(y_test, pred_linear)
#roc_auc = auc(fpr, tpr)

# Plot the ROC curve
#plt.figure(figsize=(8, 8))
#plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = {:.2f})'.format(roc_auc))
#plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
#plt.xlabel('False Positive Rate')
#plt.ylabel('True Positive Rate')
#plt.title('Receiver Operating Characteristic (ROC) Curve')
#plt.legend(loc='lower right')
#plt.show()

#start=time.time()
#svc_linear.fit(x_train,y_train.to_numpy())
#end=time.time()
#print('train period -',end-start)

#accuracy_linear = accuracy_score(y_test,pred_linear)
#precision_linear = precision_score(y_test, pred_linear, average='weighted')
#recall_linear = recall_score(y_test, pred_linear, average='weighted')
#f1_linear = f1_score(y_test, pred_linear, average='weighted')

#print("Accuracy:", accuracy_linear)
#print("Precision:", precision_linear)
#print("Recall:", recall_linear)
#print("F1 Score:", f1_linear)

#training
svm_poly.fit(x_train,y_train)
pred_poly=svm_poly.predict(x_test)
print(pred_poly)
fpr, tpr, thresholds = roc_curve(y_test, pred_poly)
roc_auc = auc(fpr, tpr)
plt.figure(figsize=(8, 8))
plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = {:.2f})'.format(roc_auc))
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.show()


#accuracy_poly = accuracy_score(y_test,pred_poly)
#precision_poly = precision_score(y_test, pred_poly, average='weighted')
#recall_poly= recall_score(y_test, pred_poly, average='weighted')
#f1_poly = f1_score(y_test, pred_poly, average='weighted')

#print("Accuracy:", accuracy_poly)
#print("Precision:", precision_poly)
#print("Recall:", recall_poly)
#print("F1 Score:", f1_poly)

#training
svm_rbdk.fit(x_train,y_train)
pred_rbdk=svm_rbdk.predict(x_test)
print(pred_rbdk)
fpr, tpr, thresholds = roc_curve(y_test, pred_rbdk)
roc_auc = auc(fpr, tpr)
plt.figure(figsize=(8, 8))
plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = {:.2f})'.format(roc_auc))
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.show()

#accuracy_rbdk = accuracy_score(y_test,pred_rbdk)
#precision_rbdk = precision_score(y_test, pred_rbdk, average='weighted')
#recall_rbdk= recall_score(y_test, pred_rbdk, average='weighted')
#f1_rbdk = f1_score(y_test, pred_rbdk, average='weighted')

#print("Accuracy:", accuracy_rbdk)
#print("Precision:", precision_rbdk)
#print("Recall:", recall_rbdk)
#print("F1 Score:", f1_rbdk)

#training
svm_sigmoid.fit(x_train,y_train)
pred_sigmoid=svm_sigmoid.predict(x_test)
print(pred_sigmoid)
fpr, tpr, thresholds = roc_curve(y_test, pred_sigmoid)
roc_auc = auc(fpr, tpr)
plt.figure(figsize=(8, 8))
plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = {:.2f})'.format(roc_auc))
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.show()


#accuracy_sigmoid = accuracy_score(y_test,pred_sigmoid)
#precision_sigmoid = precision_score(y_test, pred_sigmoid, average='weighted')
#recall_sigmoid= recall_score(y_test, pred_sigmoid, average='weighted')
#f1_sigmoid = f1_score(y_test, pred_sigmoid, average='weighted')

#print("Accuracy:", accuracy_sigmoid)
#print("Precision:", precision_sigmoid)
#print("Recall:", recall_sigmoid)
#print("F1 Score:", f1_sigmoid)
