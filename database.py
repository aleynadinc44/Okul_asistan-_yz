from sqlalchemy import create_engine, Column, Integer, String, Date, Time, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# --- SQL Server Ayarları ---
SERVER_NAME = "LAPTOP-6Q32OA4J\SQLEXPRESS" 
DATABASE_NAME = "SchoolAssistantDB" 

SQLALCHEMY_DATABASE_URL = (
    f"mssql+pyodbc://{SERVER_NAME}/{DATABASE_NAME}?driver=ODBC+Driver+17+for+SQL+Server"
)

try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    engine.connect()
    print("SQL Server bağlantısı başarılı: LAPTOP-6Q32OA4J\SQLEXPRESS/SchoolAssistantDB")
except Exception as e:
    print(f"\nFATAL HATA: SQL Server bağlantısı kurulamadı: {e}")
    exit() 

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- TABLO MODELLERİ (SCHEMA) ---
class DersProgrami(Base):
    __tablename__ = "ders_programi"
    id = Column(Integer, primary_key=True, index=True) 
    ders_adi = Column(String(100), index=True) 
    gun = Column(String(20)) 
    saat_baslangic = Column(Time) 
    sinif_no = Column(String(10))
    ogretmen_adi = Column(String(100))

class SinavTakvimi(Base):
    __tablename__ = "sinavlar"
    id = Column(Integer, primary_key=True, index=True)
    ders_adi = Column(String(100), index=True)
    sinif_duzeyi = Column(String(10)) 
    tarih = Column(Date) 
    saat = Column(Time) 
    konu = Column(String(255))
    ogretmen_adi = Column(String(100))

class Duyuru(Base):
    __tablename__ = "duyurular"
    id = Column(Integer, primary_key=True, index=True)
    baslik = Column(String(255), index=True)
    icerik = Column(String) 
    tarih = Column(Date)
    kategori = Column(String(50)) 
    yayinlayan = Column(String(100)) 

class Notlar(Base):
    __tablename__ = "notlar"
    id = Column(Integer, primary_key=True, index=True)
    ogrenci_no = Column(String(50), index=True) 
    ders_adi = Column(String(100), index=True)
    sinav_turu = Column(String(50)) 
    puan = Column(Integer) 
    etkisi = Column(Integer) 
    tarih = Column(Date) 
    
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100)) 
    email = Column(String(100), unique=True, index=True) 
    hashed_password = Column(String) 
    ogrenci_no = Column(String(50), unique=True, index=True) 
    is_active = Column(Boolean, default=True) 

# --- YENİ SERVİS TABLOSU MODELİ (SİZİN SQL'İNİZE GÖRE) ---
class ServisSaatleri(Base):
    __tablename__ = "shuttle_trips" # SQL kodunuzdaki tablo adı
    id = Column(Integer, primary_key=True, index=True) # GENERATED ALWAYS AS IDENTITY yerine bu kullanılır
    route_group = Column(String(50), index=True) 
    from_stop = Column(String(80))
    to_stop = Column(String(80)) 
    depart_time = Column(Time) 

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()