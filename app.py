import streamlit as st
import requests
from bs4 import BeautifulSoup 
import json
from typing import Optional
from datetime import datetime
import folium
from streamlit_folium import folium_static 

# --- API AYARLARI ---
FASTAPI_URL = "http://127.0.0.1:8000" 

# --- SESSION STATE (Oturum Durumu) İLKELLEŞTİRME ---
if 'logged_in' not in st.session_state: st.session_state['logged_in'] = False
if 'token' not in st.session_state: st.session_state['token'] = None
if 'user_info' not in st.session_state: st.session_state['user_info'] = None
if "messages" not in st.session_state: st.session_state.messages = []

# --- KAMPÜS AYARLARI ---
CAMPUS_COORDS = (40.9859, 28.8258) 
CAMPUS_NAME = "İstanbul Kültür Üniversitesi (Ataköy)"


def show_notes_panel(token):
    st.header("📝 Not Defterim")
    with st.form("new_note_form"):
        title = st.text_input("Başlık")
        content = st.text_area("Notunuz")
        submit = st.form_submit_button("Kaydet")
        if submit:
            headers = {"Authorization": f"Bearer {token}"}
            res = requests.post(f"{FASTAPI_URL}/notes", 
                                json={"title": title, "text_content": content}, 
                                headers=headers)
            if res.status_code == 200:
                st.success("Not kaydedildi!")
                st.rerun()

    st.divider()
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{FASTAPI_URL}/notes", headers=headers)
    if response.status_code == 200:
        notes = response.json()
        for note in notes:
            with st.expander(f"📌 {note['title']}"):
                st.write(note['content'])
                if st.button(f"Sil", key=f"del_{note['id']}"):
                    requests.delete(f"{FASTAPI_URL}/notes/{note['id']}", headers=headers)
                    st.rerun()

def get_fake_weather(lat, lon):
    current_time = datetime.now().strftime("%H:%M")
    return {"temperature": 12, "description": "Hafif Bulutlu", "wind": "15 km/s", "time": current_time}

@st.cache_data(ttl=3600)
def get_live_duyurular(url: str = "https://www.iku.edu.tr/tr/duyurular", limit: int = 5):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        duyuru_linkleri = soup.select('div.views-field-title a')
        duyurular_list = []
        for a_tag in duyuru_linkleri[:limit]:
            baslik = a_tag.get_text(strip=True)
            link = a_tag['href']
            if not link.startswith('http'): link = "https://www.iku.edu.tr" + link
            duyurular_list.append({"baslik": baslik, "link": link})
        return {"status": "success", "data": duyurular_list}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def login_user(email, password):
    try:
        response = requests.post(f"{FASTAPI_URL}/token", data={"username": email, "password": password})
        if response.status_code == 200:
            token_data = response.json()
            st.session_state['token'] = token_data['access_token']
            st.session_state['logged_in'] = True
            st.session_state['user_info'] = {"full_name": email.split('@')[0]}
            return True
        return False
    except:
        return False

def register_user(full_name, email, password, ogrenci_no):
    try:
        res = requests.post(f"{FASTAPI_URL}/register", 
                            json={"full_name": full_name, "email": email, "password": password, "ogrenci_no": ogrenci_no})
        return res.status_code == 200
    except:
        return False

def send_query(prompt):
    headers = {"Authorization": f"Bearer {st.session_state['token']}"}
    try:
        response = requests.post(f"{FASTAPI_URL}/ask", json={"prompt": prompt}, headers=headers)
        return response.json()['answer'] if response.status_code == 200 else "Hata oluştu."
    except:
        return "API bağlantı hatası."

# ----------------------------------------------------------------------
# WEB KAZIMA FONKSİYONU (Canlı Duyurular)
# ----------------------------------------------------------------------

@st.cache_data(ttl=3600) # 1 saat cache'le
def get_live_duyurular(url: str = "https://www.iku.edu.tr/tr/duyurular", limit: int = 5):
    """
    Belirtilen URL'den güncel duyuruları çeker (Web Scraping).
    HTML yapısında görülen seçiciyi (views-field-title a) hedefler.
    """
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status() 
        
        soup = BeautifulSoup(response.content, 'html.parser')
        duyurular_list = []
        
        # HTML yapısında görülen, duyuru linkini içeren etiketi hedefliyoruz.
        duyuru_linkleri = soup.select('div.views-field-title a')
        
        for a_tag in duyuru_linkleri[:limit]:
            baslik = a_tag.get_text(strip=True)
            link = a_tag['href']
            
            if baslik and len(baslik) > 10: 
                if not link.startswith('http'):
                    link = "https://www.iku.edu.tr" + link
                
                duyurular_list.append({"baslik": baslik, "link": link})
        
        return {"status": "success", "data": duyurular_list}
        
    except requests.exceptions.RequestException:
        return {"status": "error", "message": f"Web sitesine erişilemedi. Bağlantınızı kontrol edin."}
    except Exception:
        return {"status": "error", "message": f"Duyuru çekme sırasında bilinmeyen bir hata oluştu."}


# ----------------------------------------------------------------------
# YARDIMCI VE API FONKSİYONLARI (Aynı)
# ----------------------------------------------------------------------

def login_user(email: str, password: str) -> bool:
    try:
        response = requests.post(f"{FASTAPI_URL}/token", data={"username": email, "password": password})
        if response.status_code == 200:
            token_data = response.json()
            st.session_state['token'] = token_data['access_token']; st.session_state['logged_in'] = True
            st.session_state['user_info'] = {"full_name": email.split('@')[0]}
            return True
        else:
            st.error(f"Giriş Başarısız: {response.json().get('detail', 'Bilinmeyen Hata')}")
            return False
    except requests.exceptions.ConnectionError:
        st.error("API Bağlantı Hatası: Lütfen FastAPI sunucunuzun (main.py) çalıştığından emin olun.")
        return False

def register_user(full_name: str, email: str, password: str, ogrenci_no: str) -> bool:
    try:
        response = requests.post(f"{FASTAPI_URL}/register", json={"full_name": full_name, "email": email, "password": password, "ogrenci_no": ogrenci_no})
        if response.status_code == 200:
            return True
        else:
            st.error(f"Kayıt Başarısız: {response.json().get('detail', 'E-posta veya Öğrenci Numarası zaten kayıtlı.')}")
            return False
    except requests.exceptions.ConnectionError:
        st.error("API Bağlantı Hatası: Lütfen FastAPI sunucunuzun çalıştığından emin olun.")
        return False

def send_query(prompt: str) -> str:
    """ FastAPI /ask endpoint'ine metin sorgusu gönderir (DB ve CRUD araçları için). """
    if not st.session_state['token']: return "Hata: Giriş yapmadınız."
    headers = {"Authorization": f"Bearer {st.session_state['token']}", "Content-Type": "application/json"}
    try:
        response = requests.post(f"{FASTAPI_URL}/ask", json={"prompt": prompt}, headers=headers)
        if response.status_code == 200: return response.json()['answer']
        elif response.status_code == 401: st.session_state['logged_in'] = False; return "Oturumunuzun süresi doldu veya yetkiniz yok. Lütfen tekrar giriş yapın."
        else: return f"API Sorgu Hatası: {response.status_code} - {response.json().get('detail', 'Bilinmeyen Hata')}"
    except requests.exceptions.ConnectionError: return "API Bağlantı Hatası: FastAPI sunucusuna ulaşılamıyor."
    except requests.exceptions.JSONDecodeError: return "API Sorgu Hatası: Sunucudan geçersiz yanıt alındı (FastAPI çökmüş olabilir)."
        
# ----------------------------------------------------------------------
# ARAYÜZ
# ----------------------------------------------------------------------

st.set_page_config(page_title="Üniversite Asistanı EmoBot", layout="centered")
# --- CHAT ARAYÜZÜ ---
st.sidebar.title("🤖 EmoBot")

# 1. Maskot Görselini Sidebar'ın en üstüne ekleyelim
try:
    # Görselin yolu (dosya adınız neyse onu yazın)
    st.sidebar.image("maskot.png", use_container_width=True)
except:
    st.sidebar.warning("Maskot görseli (maskot.png) bulunamadı.")

# Sidebar - Önemli Linkler
st.sidebar.title("🔗 Önemli Sistemler")

st.sidebar.markdown(

    """

    * [Öğrenci Bilgi Sistemi (ORİON)](https://orion.iku.edu.tr/irj/servlet/prt/portal/prtroot/pcd!3aportal_content!2fkultur!2fKulturMobile!2fFiori?sap-config-mode=true/)

    * [Kurumsal E-posta](https://mail.iku.edu.tr/)

    * [Uzaktan Eğitim (CATS)](https://cats.iku.edu.tr/portal/)

    """

)

# Oturum Kontrolü
if not st.session_state['logged_in']:
    tab1, tab2 = st.tabs(["Giriş Yap", "Kayıt Ol"])
    
    with tab1:
        with st.form("login_form"):
            login_email = st.text_input("E-posta")
            login_password = st.text_input("Şifre", type="password")
            submit_login = st.form_submit_button("Giriş Yap")
            if submit_login:
                if login_user(login_email, login_password):
                    st.success("Giriş Başarılı!")
                    st.rerun()
                else:
                    st.error("Giriş Başarısız.")
    with tab2:
        with st.form("register_form"):
            reg_name = st.text_input("Ad Soyad")
            reg_email = st.text_input("E-posta")
            reg_pass = st.text_input("Şifre", type="password")
            reg_ogr_no = st.text_input("Öğrenci Numarası")
            if st.form_submit_button("Kayıt Ol"):
                if register_user(reg_name, reg_email, reg_pass, reg_ogr_no):
                    st.success("Kayıt başarılı! Giriş yapabilirsiniz.")

    # app.py dosyasında, kullanıcı girişi yapıldıktan sonraki "else" bloğuna gidin
else:
    

    # ... (diğer sidebar kodları: Duyurular vs.)
    # Giriş Yapılmışsa Sidebar Menüsü
    menu = st.sidebar.selectbox("İşlem Seçin", ["Asistanla Konuş", "Not Defteri"])
    st.sidebar.info(f"Hoş Geldin, **{st.session_state['user_info']['full_name']}**")
    
    if st.sidebar.button("Çıkış Yap"):
        st.session_state['logged_in'] = False
        st.rerun()

   
    if menu == "Not Defteri":
        show_notes_panel(st.session_state['token'])
    
    elif menu == "Asistanla Konuş":
        st.subheader("🛰️ Kampüs Bilgileri")
        col1, col2 = st.columns([2, 1])
        with col1:
            m = folium.Map(location=CAMPUS_COORDS, zoom_start=14)
            folium.Marker(CAMPUS_COORDS, popup=CAMPUS_NAME).add_to(m)
            folium_static(m, width=450, height=300)
        with col2:
            weather = get_fake_weather(*CAMPUS_COORDS)
            st.metric("Hava Durumu", f"{weather['temperature']}°C")
            st.write(f"**Durum:** {weather['description']}")

        st.divider()
        col_img, col_txt = st.columns([1, 4]) # Maskot ve yazı için yan yana kolonlar
        with col_img:
            try:
                # Görsel dosyanızın adı neyse onu yazın (Örn: maskot.jpg)
                st.image("maskot.png", width=100) 
            except:
                pass # Görsel yoksa hata vermez
        with col_txt:
            st.subheader("Merhaba Ben EmoBot!")
            st.write("Sana nasıl yardımcı olabilirim?")

        
    # --- DUYURULAR KISMI (Canlı Web Sitesinden) ---
    st.sidebar.title("📣 Son Duyurular")
    
    live_data = get_live_duyurular(limit=5)
    
    if live_data['status'] == 'success' and live_data['data']:
        st.sidebar.markdown("---")
        for duyuru in live_data['data']:
            st.sidebar.markdown(
                f"* [{duyuru['baslik']}]({duyuru['link']})" 
            )
        st.sidebar.markdown("---")
        st.sidebar.caption(f"Kaynak: iku.edu.tr ({len(live_data['data'])} adet)")
        
    elif live_data['status'] == 'error':
        st.sidebar.error("Canlı duyurular çekilemedi.")
        st.sidebar.caption(f"Hata: {live_data['message']}")
            
    st.markdown("---")
    # Chat Geçmişini Başlatmadan hemen önce
   
    
    # Chat Geçmişini Başlat
    if "messages" not in st.session_state:
        st.session_state.messages = []
        st.session_state.messages.append({"role": "assistant", "content": f"Merhaba {st.session_state['user_info']['full_name']}, ben Üniversite Asistanınız. Sana not ekleyebilir, silebilir, sınav güncelleyebilir ve servis saatlerini sorgulayabilirim."})

    # Geçmiş Mesajları Göster
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Yeni Kullanıcı Sorgusu (Normal Metin - DB/CRUD)
    if prompt := st.chat_input("Servis saatlerini, ders programını veya notlarını sorgula..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"): st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Asistan düşünüyor ve veritabanını kontrol ediyor..."):
                response_text = send_query(prompt)
                st.markdown(response_text)
                
        st.session_state.messages.append({"role": "assistant", "content": response_text})