# Bibliophile

Table users {
  id integer [primary key]
  username varchar
  password_salt varchar
  password_hash varchar
  email varchar
  created_at timestamp
  role_id integer [unique, not null,ref: > users_role.users_role_id]
 
}
 
Table users_role {
  users_role_id integer [primary key]
  role_name varchar
 
}
 
 
Table job_seekers {
  user_id integer [primary key, unique, not null, ref: > users.id]
  preferences text
  profile_score int
}
 
Table jobs {
  id integer [primary key]
  employer_id integer [not null, ref: > employers.user_id]
  title varchar
  description text
  skills_required text
  experience_req int
  salary_range varchar
  location varchar
  job_type varchar
  posted_at timestamp
  end_at timestamp
  is_active boolean
}
 
Table applications {
  id integer [primary key]
  job_id integer [not null, ref: > jobs.id]
  job_seeker_id integer [not null, ref: > job_seekers.user_id]
  status varchar [note: 'pending, shortlisted, rejected']
  applied_at timestamp
  match_score int
}
 
Table bookmarks {
  job_seeker_id integer [not null, ref: > job_seekers.user_id]
  job_id integer [not null, ref: > jobs.id]
  saved_at timestamp
  indexes {
    (job_seeker_id, job_id) [unique]
  }
}
 
Table premium_subscriptions {
  job_seeker_id integer [primary key, unique, not null, ref: > job_seekers.user_id]
  start_date timestamp
  end_date timestamp
  is_active boolean
}
 
Table interview_schedules {
  application_id integer [unique, not null, ref: > applications.id]
  scheduled_by integer
  scheduled_date timestamp
  contact_info text
  status varchar
}
 
Table shortlisted_candidates {
 
  employer_id integer [not null, ref: > employers.user_id]
  jobseeker_id integer [not null, ref: > job_seekers.user_id]
  job_id integer [not null, ref: > jobs.id]
  resume_path text
}
 
Table notifications {
  // id integer [primary key]
  user_id integer [not null, ref: > users.id]
  message text
  created_at timestamp
  read_status boolean
}
 
Table jobseeker_profile {
  user_id integer [primary key, ref: > job_seekers.user_id]
  profile_photo text
  aadhar_number varchar
  is_verified boolean
  skills text
  experience_years integer
  education text
  profile_completion integer
  personal_details text
}
 
Table employers {
  user_id integer [primary key, ref: > users.id]
  department varchar
  profile_photo text
  aadhar_number varchar
  is_verified boolean
  approved boolean [note: 'Set by Admin after registration']
}
