"""Bible verses module for DefSec"""
import random

ENCOURAGEMENT_VERSES = [
    ("Philippians 4:13", "I can do all things through Christ which strengtheneth me."),
    ("Isaiah 41:10", "Fear thou not; for I am with thee: be not dismayed; for I am thy God: I will strengthen thee; yea, I will help thee; yea, I will uphold thee with the right hand of my righteousness."),
    ("Psalm 28:7", "The LORD is my strength and my shield; my heart trusted in him, and I am helped: therefore my heart greatly rejoiceth; and with my song will I praise him."),
    ("Joshua 1:9", "Have not I commanded thee? Be strong and of a good courage; be not afraid, neither be thou dismayed: for the LORD thy God is with thee whithersoever thou goest."),
    ("2 Timothy 1:7", "For God hath not given us the spirit of fear; but of power, and of love, and of a sound mind."),
    ("Psalm 118:14", "The LORD is my strength and song, and is become my salvation."),
    ("Nehemiah 8:10", "The joy of the LORD is your strength."),
    ("1 Corinthians 16:13", "Watch ye, stand fast in the faith, quit you like men, be strong."),
    ("Ephesians 6:10", "Finally, my brethren, be strong in the Lord, and in the power of his might."),
    ("Deuteronomy 31:6", "Be strong and of a good courage, fear not, nor be afraid of them: for the LORD thy God, he it is that doth go with thee; he will not fail thee, nor forsake thee."),
    ("Proverbs 3:5-6", "Trust in the LORD with all thine heart; and lean not unto thine own understanding. In all thy ways acknowledge him, and he shall direct thy paths."),
    ("Matthew 17:20", "If ye have faith as a grain of mustard seed, ye shall say unto this mountain, Remove hence to yonder place; and it shall remove; and nothing shall be impossible unto you."),
    ("Romans 8:31", "What shall we then say to these things? If God be for us, who can be against us?"),
    ("Isaiah 40:31", "But they that wait upon the LORD shall renew their strength; they shall mount up with wings as eagles; they shall run, and not be weary; and they shall walk, and not faint."),
    ("Psalm 46:1", "God is our refuge and strength, a very present help in trouble."),
    ("Romans 15:13", "Now the God of hope fill you with all joy and peace in believing, that ye may abound in hope, through the power of the Holy Ghost."),
    ("2 Corinthians 12:9", "My grace is sufficient for thee: for my strength is made perfect in weakness."),
    ("Psalm 27:1", "The LORD is my light and my salvation; whom shall I fear? the LORD is the strength of my life; of whom shall I be afraid?"),
    ("James 1:5", "If any of you lack wisdom, let him ask of God, that giveth to all men liberally, and upbraideth not; and it shall be given him."),
    ("Philippians 4:6-7", "Be careful for nothing; but in every thing by prayer and supplication with thanksgiving let your requests be made known unto God. And the peace of God, which passeth all understanding, shall keep your hearts and minds through Christ Jesus.")
]

def get_random_verse():
    """Return a random encouraging Bible verse"""
    return random.choice(ENCOURAGEMENT_VERSES)