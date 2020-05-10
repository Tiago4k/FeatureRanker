import math

r_one = None
r_zero = None
b_r_one = None
b_r_zero = None
m_r_one = None
m_r_zero = None


def main(b_freq, m_freq, b_samples, m_samples):
    benign_freq = b_freq
    malware_freq = m_freq
    t_with_feature = benign_freq + malware_freq
    t_without_feature = (b_samples + m_samples) - t_with_feature

    calculate_feature_prob(
        t_with_feature, t_without_feature, b_samples, m_samples)

    calculate_sample_prob(b_freq, m_freq, t_with_feature,
                          t_without_feature, b_samples, m_samples)

    c_m = m_samples/(m_samples+b_samples)
    c_b = b_samples/(m_samples+b_samples)
    print('P(C=M) = {}/{} = {}'.format(m_samples, m_samples +
                                       b_samples, c_m))
    print('P(C=B) = {}/{} = {}'.format(b_samples, m_samples +
                                       b_samples, c_b))

    calculate_mi(c_m, c_b)


def calculate_feature_prob(t_with_feature, t_without_feature, b_samples, m_samples):
    '''Calculate the probabilty of a feature occuring in malware and benign code
    '''
    global r_one
    global r_zero

    # Probability of it occuring in both
    if r_one == None:
        r_one = round(t_with_feature/(b_samples + m_samples), 2)
        print('P(R=1) = {}/{} = {}'.format(t_with_feature,
                                           (b_samples + m_samples), r_one))

        # Recursive call
        if r_zero == None:
            calculate_feature_prob(
                t_with_feature, t_without_feature, b_samples, m_samples)

    # Probability of it NOT occuring in both
    elif r_zero == None:
        r_zero = round(t_without_feature/(b_samples + m_samples), 2)
        print('P(R=0) = {}/{} = {}'.format(t_without_feature,
                                           (b_samples + m_samples), r_zero))


def calculate_sample_prob(b_freq, m_freq, t_with_feature, t_without_feature, b_samples, m_samples):
    '''Calculate the probabilty of a sample being or not being Malware or Benign when feature occurs
    '''
    global m_r_one, b_r_one, m_r_zero, b_r_zero

    # Probability that code is Malware
    if m_r_one == None:
        m_r_one = round(m_freq/t_with_feature, 2)
        print('P(C=M|R=1) = {}/{} = {}'.format(m_freq,
                                               t_with_feature, m_r_one))

        # Recursive call
        if b_r_one == None:
            calculate_sample_prob(
                b_freq, m_freq, t_with_feature, t_without_feature, b_samples, m_samples)

    # Probability that code is Benign
    elif b_r_one == None:
        b_r_one = round(b_freq/t_with_feature, 2)
        print('P(C=B|R=1) = {}/{} = {}'.format(b_freq,
                                               t_with_feature, b_r_one))

        # Recursive call
        if m_r_zero == None:
            calculate_sample_prob(
                b_freq, m_freq, t_with_feature, t_without_feature, b_samples, m_samples)

    # Probability that code is NOT Malware
    elif m_r_zero == None:
        nonoccurance_m = m_samples - m_freq
        m_r_zero = round(nonoccurance_m/t_without_feature, 2)
        print('P(C=M|R=0) = {}/{} = {}'.format(nonoccurance_m,
                                               t_without_feature, m_r_zero))

        # Recursive call
        if b_r_zero == None:
            calculate_sample_prob(
                b_freq, m_freq, t_with_feature, t_without_feature, b_samples, m_samples)

    # Probability that code is NOT Benign
    elif b_r_zero == None:
        nonoccurance_b = b_samples - b_freq
        b_r_zero = round(nonoccurance_b/t_without_feature, 2)
        print('P(C=B|R=0) = {}/{} = {}'.format(nonoccurance_b,
                                               t_without_feature, b_r_zero))


def calculate_mi(c_m, c_b):
    global r_one, r_zero, m_r_one, b_r_one, m_r_zero, b_r_zero

    step_one_part_one = '{0} * log2({0}/{1}) + {2} * log2({2}/{3})'.format(
        b_r_zero, c_b, m_r_zero, c_m)

    step_one_part_two = '{0} * log2({0}/{1}) + {2} * log2({2}/{3})'.format(
        b_r_one, c_b, m_r_one, c_m)

    main_printer(r_zero, r_one, step_one_part_one, step_one_part_two)

    s_two_p_one_res_one = b_r_zero/c_b
    s_two_p_one_res_two = m_r_zero/c_m
    s_two_p_two_res_one = b_r_one/c_b
    s_two_p_two_res_two = m_r_one/c_m

    step_two_part_one = '{0} * log2({1}) + {2} * log2({3})'.format(
        b_r_zero, s_two_p_one_res_one, m_r_zero, s_two_p_one_res_two)
    step_two_part_two = '{0} * log2({1}) + {2} * log2({3})'.format(
        b_r_one, s_two_p_two_res_one, m_r_one, s_two_p_two_res_two)

    main_printer(r_zero, r_one, step_two_part_one, step_two_part_two)

    s_three_p_one_res_one = round(math.log2(s_two_p_one_res_one), 2)
    s_three_p_one_res_two = round(math.log2(s_two_p_one_res_two), 2)
    s_three_p_two_res_one = round(math.log2(s_two_p_two_res_one), 2)
    s_three_p_two_res_two = round(math.log2(s_two_p_two_res_two), 2)

    step_three_part_one = '{} * {} + {} * {}'.format(
        b_r_zero, s_three_p_one_res_one, m_r_zero, s_three_p_one_res_two)
    step_three_part_two = '{} * {} + {} * {}'.format(
        b_r_one, s_three_p_two_res_one, m_r_one, s_three_p_two_res_two)

    main_printer(r_zero, r_one, step_three_part_one, step_three_part_two)

    s_four_p_one_res_one = round(b_r_zero * s_three_p_one_res_one, 2)
    s_four_p_one_res_two = round(m_r_zero * s_three_p_one_res_two, 2)
    s_four_p_two_res_one = round(b_r_one * s_three_p_two_res_one, 2)
    s_four_p_two_res_two = round(m_r_one * s_three_p_two_res_two, 2)

    if s_four_p_one_res_two < 0:
        s_four_p_one_res_two = abs(s_four_p_one_res_two)
    if s_four_p_two_res_two < 0:
        s_four_p_two_res_two = abs(s_four_p_two_res_two)

    step_four_part_one = '{} - {}'.format(
        s_four_p_one_res_one, s_four_p_one_res_two)
    step_four_part_two = '{} - {}'.format(
        s_four_p_two_res_one, s_four_p_two_res_two)

    main_printer(r_zero, r_one, step_four_part_one, step_four_part_two)

    if s_four_p_one_res_one < 0:
        s_five_res_one = round(s_four_p_one_res_one + s_four_p_one_res_two, 2)
    else:
        s_five_res_one = round(s_four_p_one_res_one - s_four_p_one_res_two, 2)

    if s_four_p_two_res_one < 0:
        s_five_res_two = round(
            s_four_p_two_res_one + s_four_p_two_res_two, 2)
    else:
        s_five_res_two = round(
            s_four_p_two_res_one - s_four_p_two_res_two, 2)

    print('= {} * ({}) + {} * ({})'.format(r_zero,
                                           s_five_res_one, r_one, s_five_res_two))

    s_six_res_one = round(r_zero * s_five_res_one, 4)
    s_six_res_two = round(r_one * s_five_res_two, 4)

    print('= {} + {}'.format(s_six_res_one, s_six_res_two))

    mi = s_six_res_one + s_six_res_two
    print('MI = {}'.format(mi))


def main_printer(r_zero, r_one, part_one, part_two):

    print('= {} * ({})'.format(r_zero, part_one))
    print('+ {} * ({})'.format(r_one, part_two))


def user_values():

    b_freq = input('Enter feature frequency in Benign apps: ')
    m_freq = input('Enter feature frequency in Malware apps: ')
    b_samples = input('Enter total number of Benign samples: ')
    m_samples = input('Enter total number of Malware samples: ')
    print('*' * 50)

    main(int(b_freq), int(m_freq), int(b_samples), int(m_samples))


if __name__ == '__main__':

    user_values()

    # main(42, 742, 1000, 1000)
