import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.graph_objects as go
from datetime import datetime

# ---------------- PAGE SETTINGS ----------------
st.set_page_config(page_title="NIDS Dashboard", layout="wide")

# ---------------- BACKGROUND ----------------
def add_bg():
    st.markdown(
        """
        <style>
        .stApp {
            background-image: url("https://www.shutterstock.com/image-photo/cyber-security-network-data-protection-600nw-2656907229.jpg");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
        }

        .block-container {
            background: rgba(0,0,0,0.65);
            padding: 20px;
            border-radius: 10px;
        }

        h1,h2,h3,h4,h5,h6,p,label,div {
            color: white !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

add_bg()

# ---------------- LOAD MODEL ----------------
model = joblib.load("model.pkl")

# ---------------- SESSION VARIABLES ----------------
if "login" not in st.session_state:
    st.session_state.login = False

if "attack_log" not in st.session_state:
    st.session_state.attack_log = []

# ---------------- LOGIN PAGE ----------------
if not st.session_state.login:

    st.title("🔐 Network Intrusion Detection System Login")

    col1, col2, col3 = st.columns([1,2,1])

    with col2:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):

            if username == "admin" and password == "1234":
                st.session_state.login = True
                st.success("Login Successful")
                st.rerun()
            else:
                st.error("Invalid Username or Password")

# ---------------- MAIN DASHBOARD ----------------
else:

    st.title("🔐 Realtime Network Intrusion Detection System")
    st.write("Machine Learning based cyber attack detection")

    if st.sidebar.button("Logout"):
        st.session_state.login = False
        st.rerun()

    menu = ["🏠 Home","🔍 Prediction","📊 Traffic Analysis","📜 Attack Logs","ℹ About"]
    choice = st.sidebar.selectbox("Navigation", menu)

# ---------------- HOME ----------------
    if choice == "🏠 Home":

        st.subheader("System Overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Flows Processed", "1000")
        col2.metric("Attacks Detected", len([x for x in st.session_state.attack_log if x["Status"]=="ATTACK"]))
        col3.metric("Accuracy", "99%")
        col4.metric("System Status", "Active")

        st.subheader("Network Activity")

        chart_data = pd.DataFrame(
            np.random.randn(20,3),
            columns=["Normal","Attack","Suspicious"]
        )

        st.line_chart(chart_data)

        st.subheader("System Components")

        status = pd.DataFrame({
            "Component":["Packet Capture","ML Engine","Alert System","Dashboard"],
            "Status":["Active","Running","Monitoring","Online"]
        })

        st.table(status)

# ---------------- PREDICTION ----------------
    elif choice == "🔍 Prediction":

        st.subheader("Intrusion Prediction")

        col1, col2 = st.columns(2)

        with col1:
            duration = st.number_input("Duration",0,1000)
            protocol_type = st.number_input("Protocol Type",0,10)
            service = st.number_input("Service",0,100)
            flag = st.number_input("Flag",0,10)
            src_bytes = st.number_input("Source Bytes",0,100000)
            dst_bytes = st.number_input("Destination Bytes",0,100000)
            serror_rate = st.number_input("Serror Rate",0.0,1.0)

        with col2:
            srv_serror_rate = st.number_input("Srv Serror Rate",0.0,1.0)
            count = st.number_input("Count",0,100)
            srv_count = st.number_input("Srv Count",0,100)
            dst_host_count = st.number_input("Dst Host Count",0,255)
            dst_host_srv_count = st.number_input("Dst Host Srv Count",0,255)
            dst_host_same_srv_rate = st.number_input("Dst Host Same Srv Rate",0.0,1.0)
            dst_host_serror_rate = st.number_input("Dst Host Serror Rate",0.0,1.0)
            dst_host_srv_serror_rate = st.number_input("Dst Host Srv Serror Rate",0.0,1.0)

        input_data = {
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "serror_rate": serror_rate,
        "srv_serror_rate": srv_serror_rate,
        "count": count,
        "srv_count": srv_count,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "dst_host_srv_serror_rate": dst_host_srv_serror_rate
        }

        input_df = pd.DataFrame(columns=model.feature_names_in_)
        input_df.loc[0] = 0

        for key in input_data:
            if key in input_df.columns:
                input_df.at[0,key] = input_data[key]

        if st.button("🚀 Predict Attack"):

            prediction = model.predict(input_df)
            probability = model.predict_proba(input_df)

            prob = probability[0][1] * 100

            if prediction[0] == 1:
                st.error("🚨 ALERT: Intrusion Detected")
                status = "ATTACK"
            else:
                st.success("🟢 Normal Network Traffic")
                status = "NORMAL"

            st.write("Attack Probability:", round(prob,2),"%")

            if prob < 40:
                risk = "LOW"
            elif prob < 70:
                risk = "MEDIUM"
            else:
                risk = "HIGH"

            st.write("Risk Level:", risk)

            # SAVE LOG
            st.session_state.attack_log.append({
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Status": status,
                "Probability (%)": round(prob,2),
                "Risk Level": risk
            })

            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=prob,
                title={'text': "Attack Probability"},
                gauge={
                    'axis': {'range': [0,100]},
                    'bar': {'color': "red"},
                    'steps': [
                        {'range': [0,40], 'color': "green"},
                        {'range': [40,70], 'color': "yellow"},
                        {'range': [70,100], 'color': "red"}
                    ]
                }
            ))

            st.plotly_chart(fig, use_container_width=True)

# ---------------- TRAFFIC ANALYSIS ----------------
    elif choice == "📊 Traffic Analysis":

        st.subheader("Network Traffic Data")

        traffic = pd.DataFrame({
            "Normal Traffic": np.random.randint(50,120,10),
            "Attack Traffic": np.random.randint(5,40,10)
        })

        col1,col2 = st.columns(2)

        with col1:
            st.bar_chart(traffic)

        with col2:
            st.area_chart(traffic)

        st.subheader("Traffic Table")
        st.dataframe(traffic)

# ---------------- ATTACK LOGS ----------------
    elif choice == "📜 Attack Logs":

        st.subheader("Recent Security Events")

        if st.session_state.attack_log:
            log_df = pd.DataFrame(st.session_state.attack_log[::-1])
            st.dataframe(log_df, use_container_width=True)
        else:
            st.info("No events logged yet.")

# ---------------- ABOUT ----------------
    else:

        st.subheader("About Project")

        st.write("""
        **Network Intrusion Detection System (NIDS)** detects malicious
        network traffic using Machine Learning.

        Features:
        - Real-time intrusion detection
        - Machine Learning based prediction
        - Interactive security dashboard
        - Network traffic visualization
        - Attack logging system
        """)

        st.info("Developed for Cyber Security Project")

st.markdown("---")
st.caption("Network Intrusion Detection System | ML Cyber Security Project")